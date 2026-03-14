package io.contexa.contexacore.autonomous.tiered.strategy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
public abstract class AbstractTieredStrategy implements ThreatEvaluationStrategy {

    protected final UnifiedLLMOrchestrator llmOrchestrator;
    protected final SecurityEventEnricher eventEnricher;
    protected final SecurityPromptTemplate promptTemplate;
    protected final BehaviorVectorService behaviorVectorService;
    protected final UnifiedVectorService unifiedVectorService;
    protected final BaselineLearningService baselineLearningService;
    protected final TieredStrategyProperties tieredStrategyProperties;

    private static final Cache<String, SecurityPromptTemplate.SessionContext> ESCALATION_SESSION_CACHE =
            Caffeine.newBuilder()
                    .maximumSize(1000)
                    .expireAfterWrite(30, TimeUnit.MINUTES)
                    .build();

    private static final Cache<String, SecurityPromptTemplate.BehaviorAnalysis> ESCALATION_BEHAVIOR_CACHE =
            Caffeine.newBuilder()
                    .maximumSize(1000)
                    .expireAfterWrite(30, TimeUnit.MINUTES)
                    .build();

    private static final Cache<String, List<Document>> ESCALATION_RAG_CACHE =
            Caffeine.newBuilder()
                    .maximumSize(500)
                    .expireAfterWrite(30, TimeUnit.MINUTES)
                    .build();

    protected AbstractTieredStrategy(
            UnifiedLLMOrchestrator llmOrchestrator,
            SecurityEventEnricher eventEnricher,
            SecurityPromptTemplate promptTemplate,
            BehaviorVectorService behaviorVectorService,
            UnifiedVectorService unifiedVectorService,
            BaselineLearningService baselineLearningService,
            TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate
            : new SecurityPromptTemplate(this.eventEnricher, tieredStrategyProperties);
        this.behaviorVectorService = behaviorVectorService;
        this.unifiedVectorService = unifiedVectorService;
        this.baselineLearningService = baselineLearningService;
        this.tieredStrategyProperties = tieredStrategyProperties;
    }

    protected abstract String getLayerName();

    @Override
    public String getStrategyName() {
        return getLayerName();
    }

    protected static void cacheEscalationContext(String eventId,
                                                  SecurityPromptTemplate.SessionContext sessionCtx,
                                                  SecurityPromptTemplate.BehaviorAnalysis behaviorCtx,
                                                  List<Document> ragDocuments) {
        if (eventId == null) return;
        if (sessionCtx != null) ESCALATION_SESSION_CACHE.put(eventId, sessionCtx);
        if (behaviorCtx != null) ESCALATION_BEHAVIOR_CACHE.put(eventId, behaviorCtx);
        if (ragDocuments != null && !ragDocuments.isEmpty()) ESCALATION_RAG_CACHE.put(eventId, ragDocuments);
    }

    protected static SecurityPromptTemplate.SessionContext getCachedSessionContext(String eventId) {
        return eventId != null ? ESCALATION_SESSION_CACHE.getIfPresent(eventId) : null;
    }

    protected static SecurityPromptTemplate.BehaviorAnalysis getCachedBehaviorAnalysis(String eventId) {
        return eventId != null ? ESCALATION_BEHAVIOR_CACHE.getIfPresent(eventId) : null;
    }

    protected static List<Document> getCachedRagDocuments(String eventId) {
        return eventId != null ? ESCALATION_RAG_CACHE.getIfPresent(eventId) : null;
    }

    protected SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            String cleanedJson = extractJsonObject(jsonResponse);
            SecurityResponse response = SecurityResponse.fromJson(cleanedJson);
            if (response != null && response.isValid()) {
                return validateAndFixResponse(response);
            }
            log.error("[{}] JSON parsing failed, returning default response", getLayerName());
            return createDefaultResponse();
        } catch (Exception e) {
            log.error("[{}] JSON response parsing failed", getLayerName(), e);
            return createDefaultResponse();
        }
    }

    protected SecurityResponse validateAndFixResponse(SecurityResponse response) {
        if (response == null) return createDefaultResponse();
        double[] validated = validateResponseBase(response.getRiskScore(), response.getConfidence());
        response.setRiskScore(validated[0]);
        response.setConfidence(validated[1]);
        if (response.getAction() != null && !response.getAction().isBlank()) {
            ZeroTrustAction mapped = ZeroTrustAction.fromString(response.getAction());
            response.setAction(mapped.name());
        } else {
            response.setAction(ZeroTrustAction.ESCALATE.name());
        }
        return response;
    }

    protected SecurityResponse createDefaultResponse() {
        return SecurityResponse.builder()
                .riskScore(null)
                .confidence(null)
                .action(ZeroTrustAction.ESCALATE.name())
                .reasoning("[AI Native] " + getLayerName() + " LLM analysis unavailable")
                .mitre(null)
                .build();
    }

    protected SecurityDecision convertToSecurityDecisionBase(SecurityResponse response, SecurityEvent event) {
        if (response == null) response = createDefaultResponse();
        ZeroTrustAction action = mapStringToAction(response.getAction());
        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
                .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                .reasoning(response.getReasoning())
                .eventId(event != null ? event.getEventId() : "unknown")
                .analysisTime(System.currentTimeMillis())
                .build();
        if (response.getMitre() != null && !response.getMitre().isBlank()) {
            decision.setThreatCategory(response.getMitre());
        }
        if (response.getEvidence() != null) {
            decision.setEvidence(response.getEvidence());
        }
        if (response.getLegitimateHypothesis() != null) {
            decision.setLegitimateHypothesis(response.getLegitimateHypothesis());
        }
        if (response.getSuspiciousHypothesis() != null) {
            decision.setSuspiciousHypothesis(response.getSuspiciousHypothesis());
        }
        return decision;
    }

    protected List<String> extractSimilarEventsSummary(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return Collections.emptyList();
        }

        return documents.stream()
                .limit(5)
                .map(doc -> {
                    Map<String, Object> meta = doc.getMetadata();
                    double score = extractSimilarityScore(doc);
                    int similarityPct = (int) (score * 100);

                    StringBuilder summary = new StringBuilder();
                    String docType = String.valueOf(meta.get("documentType"));
                    switch (docType) {
                        case "threat" -> summary.append("[BLOCKED] ");
                        case "suspicious" -> summary.append("[CHALLENGED] ");
                        case "ambiguous" -> summary.append("[ESCALATED] ");
                        default -> {}
                    }
                    summary.append(String.format("Similarity:%d%%", similarityPct));

                    appendMetaIfPresent(summary, meta, "sourceIp", "IP");
                    appendMetaIfPresent(summary, meta, "requestPath", "Path");
                    appendMetaIfPresent(summary, meta, "hour", "Hour");
                    appendMetaIfPresent(summary, meta, "dayOfWeek", "Day");
                    appendMetaIfPresent(summary, meta, "userAgentOS", "OS");
                    appendMetaIfPresent(summary, meta, "userAgentBrowser", "UA");
                    appendMetaIfPresent(summary, meta, "riskScore", "Risk");
                    appendMetaIfPresent(summary, meta, "confidence", "Conf");
                    appendMetaIfPresent(summary, meta, "action", "Action");

                    String content = doc.getText();
                    if (content != null && !content.isBlank()) {
                        int maxPreview = "threat".equals(docType) ? 400 : 300;
                        String truncated = content.length() > maxPreview
                                ? content.substring(0, maxPreview) + "..."
                                : content;
                        summary.append("\n  ").append(truncated);
                    }

                    return summary.toString();
                })
                .collect(Collectors.toList());
    }

    protected static double extractSimilarityScore(Document doc) {
        Double docScore = doc.getScore();
        if (docScore != null) {
            return docScore;
        }
        Map<String, Object> meta = doc.getMetadata();
        Object scoreObj = meta.get(VectorDocumentMetadata.SIMILARITY_SCORE);
        if (scoreObj == null) scoreObj = meta.get("score");
        if (scoreObj == null) scoreObj = meta.get("distance");
        if (scoreObj instanceof Number) {
            return ((Number) scoreObj).doubleValue();
        }
        return 0.0;
    }

    private static void appendMetaIfPresent(StringBuilder sb, Map<String, Object> meta,
                                             String key, String label) {
        Object val = meta.get(key);
        if (val != null && !val.toString().isEmpty()) {
            sb.append(", ").append(label).append(":").append(val);
        }
    }

    protected ZeroTrustAction mapStringToAction(String action) {
        ZeroTrustAction zta = ZeroTrustAction.fromString(action);
        if (zta == ZeroTrustAction.ESCALATE && action != null && !action.isBlank()) {
            String upper = action.trim().toUpperCase();
            if (!ZeroTrustAction.ESCALATE.name().equals(upper) && !"E".equals(upper)) {
                log.error("[{}] Unknown action '{}' from LLM, converting to ESCALATE",
                        getLayerName(), action);
            }
        }
        return zta;
    }

    protected double[] validateResponseBase(Double riskScore, Double confidence) {
        double validatedRiskScore;
        double validatedConfidence;

        if (riskScore == null) {
            log.error("[{}] LLM returned no riskScore, using NaN", getLayerName());
            validatedRiskScore = Double.NaN;
        } else {
            validatedRiskScore = Math.max(0.0, Math.min(1.0, riskScore));
        }

        if (confidence == null) {
            log.error("[{}] LLM returned no confidence, using NaN", getLayerName());
            validatedConfidence = Double.NaN;
        } else {
            validatedConfidence = Math.max(0.0, Math.min(1.0, confidence));
        }

        return new double[]{validatedRiskScore, validatedConfidence};
    }

    protected BaseBehaviorAnalysis analyzeBehaviorPatternsBase(SecurityEvent event,
                                                                 BaselineLearningService baselineLearningService,
                                                                 List<String> similarEvents) {
        BaseBehaviorAnalysis analysis = new BaseBehaviorAnalysis();
        String userId = event.getUserId();
        analysis.setSimilarEvents(similarEvents != null ? similarEvents : Collections.emptyList());
        if (baselineLearningService == null) {
            analysis.setBaselineContext("[SERVICE_UNAVAILABLE] Baseline learning service not configured");
            analysis.setBaselineEstablished(false);
        } else if (userId == null) {
            log.error("[{}][SYSTEM_ERROR] userId is null - authentication system failure", getLayerName());
            analysis.setBaselineContext("[SYSTEM_ERROR] Authentication failure - userId unavailable. " +
                "This should not happen in authenticated platform. Recommend ESCALATE.");
            analysis.setBaselineEstablished(false);
        } else {
            try {
                String baselineContext = baselineLearningService.buildBaselinePromptContext(userId, event);

                if (baselineContext == null || baselineContext.isEmpty()) {
                    analysis.setBaselineContext("[NO_DATA] Baseline service returned empty response");
                } else {
                    analysis.setBaselineContext(baselineContext);
                }
                analysis.setBaselineEstablished(baselineLearningService.getBaseline(userId) != null);

            } catch (Exception e) {
                log.error("[{}] Baseline service error for user {}: {}", getLayerName(), userId, e.getMessage());
                analysis.setBaselineContext("[SERVICE_ERROR] Baseline service error: " + e.getMessage());
                analysis.setBaselineEstablished(false);
            }
        }

        return analysis;
    }

    protected List<Document> searchRelatedContextBase(SecurityEvent event,
                                                       int topK,
                                                       double similarityThreshold) {
        if (unifiedVectorService == null) {
            return Collections.emptyList();
        }
        try {
            StringBuilder queryBuilder = new StringBuilder();

            if (event.getSourceIp() != null) {
                queryBuilder.append("IP: ").append(event.getSourceIp());
            }

            String targetResource = eventEnricher.getTargetResource(event).orElse(null);
            if (targetResource != null && !targetResource.isEmpty()) {
                if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                queryBuilder.append("Path: ").append(targetResource);
            }

            String currentOS = SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent());
            if (currentOS != null && !"Desktop".equals(currentOS)) {
                if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                queryBuilder.append("OS: ").append(currentOS);
            }

            String browser = SecurityEventEnricher.extractBrowserSignature(event.getUserAgent());
            if (browser != null) {
                if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                queryBuilder.append("UA: ").append(browser);
            }

            if (event.getTimestamp() != null) {
                int hour = event.getTimestamp().getHour();
                if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                queryBuilder.append("Hour: ").append(hour);
            }

            Map<String, Object> meta = event.getMetadata();
            if (meta != null) {
                Object httpMethod = meta.get("httpMethod");
                if (httpMethod != null) {
                    if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                    queryBuilder.append("Method: ").append(httpMethod);
                }

                if (Boolean.TRUE.equals(meta.get("isNewDevice"))) {
                    if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                    queryBuilder.append("NewDevice: true");
                }

                if (Boolean.TRUE.equals(meta.get("isSensitiveResource"))) {
                    if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                    queryBuilder.append("SensitiveResource: true");
                }
            }

            String query = queryBuilder.toString().trim();
            if (query.isEmpty()) {
                return Collections.emptyList();
            }

            String userId = event.getUserId();
            if (userId == null || userId.isEmpty() || "unknown".equals(userId)) {
                log.error("[{}] userId missing - skipping RAG search for account isolation",
                    getLayerName());
                return Collections.emptyList();
            }

            FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
            Filter.Expression filter = filterBuilder.and(
                filterBuilder.or(
                    filterBuilder.or(
                        filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()),
                        filterBuilder.eq("documentType", VectorDocumentType.THREAT.getValue())
                    ),
                    filterBuilder.or(
                        filterBuilder.eq("documentType", VectorDocumentType.SUSPICIOUS.getValue()),
                        filterBuilder.eq("documentType", VectorDocumentType.AMBIGUOUS.getValue())
                    )
                ),
                filterBuilder.eq("userId", userId)
            ).build();

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(topK)
                    .similarityThreshold(similarityThreshold)
                    .filterExpression(filter)
                    .build();

            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);

            return documents != null ? documents : Collections.emptyList();

        } catch (Exception e) {
            log.error("[{}] Vector store context search failed", getLayerName(), e);
            return Collections.emptyList();
        }
    }

    protected static class BaseSessionContext {
        protected String sessionId;
        protected String userId;
        protected String authMethod;
        protected LocalDateTime startTime;
        protected String ipAddress;
        protected String userAgent;
        protected List<String> recentActions = new ArrayList<>();
        protected int accessFrequency = 0;

        public boolean isValid() {
            return startTime != null;
        }

        public long getSessionDuration() {
            if (startTime == null) return 0;
            return Duration.between(startTime, LocalDateTime.now()).toMinutes();
        }

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }

        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

        public List<String> getRecentActions() { return recentActions; }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        public int getAccessFrequency() { return accessFrequency; }
        public void setAccessFrequency(int accessFrequency) { this.accessFrequency = accessFrequency; }
    }


    protected static class BaseBehaviorAnalysis {
        protected List<String> similarEvents = new ArrayList<>();
        protected String baselineContext;
        protected boolean baselineEstablished;

        public List<String> getSimilarEvents() { return similarEvents; }
        public void setSimilarEvents(List<String> events) { this.similarEvents = events; }

        public String getBaselineContext() { return baselineContext; }
        public void setBaselineContext(String baselineContext) { this.baselineContext = baselineContext; }

        public boolean isBaselineEstablished() { return baselineEstablished; }
        public void setBaselineEstablished(boolean baselineEstablished) { this.baselineEstablished = baselineEstablished; }
    }


    protected String extractJsonObject(String response) {
        if (response == null || response.isEmpty()) {
            return "{}";
        }

        int startIndex = response.indexOf('{');
        if (startIndex == -1) {
            return response;
        }

        int braceCount = 0;
        int endIndex = -1;
        boolean inString = false;
        boolean escaped = false;

        for (int i = startIndex; i < response.length(); i++) {
            char c = response.charAt(i);

            if (escaped) {
                escaped = false;
                continue;
            }

            if (c == '\\') {
                escaped = true;
                continue;
            }

            if (c == '"') {
                inString = !inString;
                continue;
            }

            if (!inString) {
                if (c == '{') {
                    braceCount++;
                } else if (c == '}') {
                    braceCount--;
                    if (braceCount == 0) {
                        endIndex = i;
                        break;
                    }
                }
            }
        }
        if (endIndex != -1) {
            return response.substring(startIndex, endIndex + 1);
        }
        endIndex = response.lastIndexOf('}');
        if (endIndex > startIndex) {
            return response.substring(startIndex, endIndex + 1);
        }
        return response;
    }

    protected Map<String, Object> buildAnalysisContext(SecurityPromptTemplate.SessionContext sessionCtx,
                                                       SecurityPromptTemplate.BehaviorAnalysis behaviorCtx, List<Document> relatedDocuments) {
        Map<String, Object> context = new HashMap<>();
        if (sessionCtx != null) {
            context.put("sessionContext", sessionCtx);
        }
        if (behaviorCtx != null) {
            context.put("behaviorAnalysis", behaviorCtx);
        }
        if (relatedDocuments != null && !relatedDocuments.isEmpty()) {
            context.put("relatedDocuments", relatedDocuments);
        }
        return context;
    }
}
