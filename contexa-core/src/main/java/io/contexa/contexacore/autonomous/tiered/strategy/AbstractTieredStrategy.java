package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
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
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public abstract class AbstractTieredStrategy implements ThreatEvaluationStrategy {

    protected final UnifiedLLMOrchestrator llmOrchestrator;
    protected final RedisTemplate<String, Object> redisTemplate;
    protected final SecurityEventEnricher eventEnricher;
    protected final SecurityPromptTemplate promptTemplate;
    protected final BehaviorVectorService behaviorVectorService;
    protected final UnifiedVectorService unifiedVectorService;
    protected final BaselineLearningService baselineLearningService;
    protected final TieredStrategyProperties tieredStrategyProperties;

    protected AbstractTieredStrategy(
            UnifiedLLMOrchestrator llmOrchestrator,
            RedisTemplate<String, Object> redisTemplate,
            SecurityEventEnricher eventEnricher,
            SecurityPromptTemplate promptTemplate,
            BehaviorVectorService behaviorVectorService,
            UnifiedVectorService unifiedVectorService,
            BaselineLearningService baselineLearningService,
            TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.redisTemplate = redisTemplate;
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

    protected List<String> extractSimilarEventsSummary(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return Collections.emptyList();
        }

        return documents.stream()
                .limit(5)
                .map(doc -> {
                    Map<String, Object> meta = doc.getMetadata();
                    double score = 0.0;
                    Object scoreObj = meta.get("similarityScore");
                    if (scoreObj instanceof Number) {
                        score = ((Number) scoreObj).doubleValue();
                    }
                    int similarityPct = (int) (score * 100);
                    return String.format("EventID:%s, Similarity:%d%%",
                            meta.get("eventId"), similarityPct);
                })
                .collect(Collectors.toList());
    }

    protected SecurityDecision.Action mapStringToAction(String action) {
        if (action == null) return SecurityDecision.Action.ESCALATE;

        String upperAction = action.toUpperCase().trim();

        return switch (upperAction) {
            case "ALLOW", "A" -> SecurityDecision.Action.ALLOW;
            case "BLOCK", "B" -> SecurityDecision.Action.BLOCK;
            case "CHALLENGE", "C" -> SecurityDecision.Action.CHALLENGE;
            default -> {
                if (!"ESCALATE".equals(upperAction) && !"E".equals(upperAction)) {
                    log.error("[{}] Unknown action '{}' from LLM, converting to ESCALATE",
                            getLayerName(), action);
                }
                yield SecurityDecision.Action.ESCALATE;
            }
        };
    }

    protected double[] validateResponseBase(Double riskScore, Double confidence) {
        double validatedRiskScore = (riskScore != null) ? riskScore : Double.NaN;
        double validatedConfidence = (confidence != null) ? confidence : Double.NaN;

        if (riskScore == null) {
            log.error("[{}] LLM returned no riskScore, using NaN", getLayerName());
        }
        if (confidence == null) {
            log.error("[{}] LLM returned no confidence, using NaN", getLayerName());
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

            if (event.getUserId() != null && !event.getUserId().equals("unknown")) {
                queryBuilder.append("User: ").append(event.getUserId());
            }

            if (event.getSourceIp() != null) {
                if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                queryBuilder.append("IP: ").append(event.getSourceIp());
            }

            String targetResource = eventEnricher.getTargetResource(event).orElse(null);
            if (targetResource != null && !targetResource.isEmpty()) {
                if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                queryBuilder.append("Path: ").append(targetResource);
            }

            String currentOS = extractOSFromUserAgent(event.getUserAgent());
            if (currentOS != null && !"Desktop".equals(currentOS)) {
                if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                queryBuilder.append("OS: ").append(currentOS);
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
                filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()),
                filterBuilder.eq("userId", userId)
            ).build();

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(topK)
                    .similarityThreshold(similarityThreshold)
                    .filterExpression(filter)
                    .build();

            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);

            return documents != null ? documents : java.util.Collections.emptyList();

        } catch (Exception e) {
            log.error("[{}] Vector store context search failed", getLayerName(), e);
            return java.util.Collections.emptyList();
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


    protected String extractOSFromUserAgent(String userAgent) {
        return SecurityEventEnricher.extractOSFromUserAgent(userAgent);
    }

    protected String extractBrowserSignature(String userAgent) {
        return SecurityEventEnricher.extractBrowserSignature(userAgent);
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

        // fallback: use last '}' character
        endIndex = response.lastIndexOf('}');
        if (endIndex > startIndex) {
            return response.substring(startIndex, endIndex + 1);
        }

        return response;
    }
}