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
            : new SecurityPromptTemplate(this.eventEnricher, tieredStrategyProperties, baselineLearningService);
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
                    log.warn("[{}][AI Native] Unknown action '{}' detected. Converting to ESCALATE",
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
            log.warn("[{}][AI Native] LLM이 riskScore 미반환 (가공 없이 NaN 사용)", getLayerName());
        }
        if (confidence == null) {
            log.warn("[{}][AI Native] LLM이 confidence 미반환 (가공 없이 NaN 사용)", getLayerName());
        }

        return new double[]{validatedRiskScore, validatedConfidence};
    }

    protected Map<String, Object> buildBaseMetadata(SecurityEvent event, SecurityDecision decision, String documentType) {
        Map<String, Object> metadata = new HashMap<>();

        metadata.put("documentType", documentType);
        String eventTimestamp = event.getTimestamp() != null
            ? event.getTimestamp().toString()
            : LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        metadata.put("timestamp", eventTimestamp);
        if (event.getTimestamp() != null) {
            metadata.put("hour", event.getTimestamp().getHour());
        }
        if (event.getEventId() != null) {
            metadata.put("eventId", event.getEventId());
        }
        if (event.getUserId() != null) {
            metadata.put("userId", event.getUserId());
        }
        if (event.getSourceIp() != null) {
            metadata.put("sourceIp", event.getSourceIp());
        }
        if (event.getSessionId() != null) {
            metadata.put("sessionId", event.getSessionId());
        }

        if (event.getUserAgent() != null && !event.getUserAgent().isEmpty()) {
            metadata.put("userAgent", event.getUserAgent());
            String userAgentOS = extractOSFromUserAgent(event.getUserAgent());
            if (userAgentOS != null) {
                metadata.put("userAgentOS", userAgentOS);
            }
        }
        if (decision.getThreatCategory() != null) {
            metadata.put("threatCategory", decision.getThreatCategory());
        }

        return metadata;
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
                    log.debug("[{}] Baseline context generated for user {}", getLayerName(), userId);
                }
                analysis.setBaselineEstablished(baselineLearningService.getBaseline(userId) != null);

            } catch (Exception e) {
                log.warn("[{}] Baseline service error for user {}: {}", getLayerName(), userId, e.getMessage());
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
                log.debug("[{}][AI Native] Empty query, skipping vector search for event {}",
                    getLayerName(), event.getEventId());
                return Collections.emptyList();
            }

            String userId = event.getUserId();
            if (userId == null || userId.isEmpty() || "unknown".equals(userId)) {
                log.warn("[{}][AI Native v8.5] userId 없음 - RAG 검색 스킵 (계정 격리 보호)",
                    getLayerName());
                return Collections.emptyList();
            }

            FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
            Filter.Expression filter = filterBuilder.and(
                filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()),
                filterBuilder.eq("userId", userId)
            ).build();
            log.debug("[{}][AI Native v8.5] RAG search with userId filter: {}", getLayerName(), userId);

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(topK)
                    .similarityThreshold(similarityThreshold)
                    .filterExpression(filter)
                    .build();

            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);

            log.debug("[{}] RAG behavioral context search: {} documents found for event {}",
                getLayerName(), documents != null ? documents.size() : 0, event.getEventId());

            return documents != null ? documents : java.util.Collections.emptyList();

        } catch (Exception e) {
            log.debug("[{}] Vector store context search failed", getLayerName(), e);
            return java.util.Collections.emptyList();
        }
    }

    protected static class BaseSessionContext {
        protected String sessionId;
        protected String userId;
        protected String authMethod;
        protected LocalDateTime startTime;
        protected String ipAddress;
        protected String userAgent;  // AI Native v6.0: 세션 하이재킹 탐지용
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
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        // 모바일 OS 우선 검사 (Android가 Linux를 포함하므로)
        if (userAgent.contains("Android")) {
            return "Android";
        }
        // AI Native v8.8: iPod 추가 (드물지만 존재)
        if (userAgent.contains("iPhone") || userAgent.contains("iPad")
                || userAgent.contains("iPod") || userAgent.contains("iOS")) {
            return "iOS";
        }

        // 데스크톱 OS
        if (userAgent.contains("Windows NT") || userAgent.contains("Windows")) {
            return "Windows";
        }
        if (userAgent.contains("Mac OS X") || userAgent.contains("Macintosh")) {
            return "Mac";
        }
        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }
        if (userAgent.contains("Linux")) {
            return "Linux";
        }

        // 모바일 패턴 감지 (OS 특정 불가 시)
        if (userAgent.contains("Mobile") || userAgent.contains("Tablet")) {
            return "Mobile";
        }

        // 기본값: Desktop (unknown 대신)
        return "Desktop";
    }

    protected String extractBrowserSignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        // Edge (Chromium 기반이므로 Chrome보다 먼저 검사)
        if (userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Edg/", "Edge");
        }

        // Chrome
        if (userAgent.contains("Chrome/") && !userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Chrome/", "Chrome");
        }

        // Firefox
        if (userAgent.contains("Firefox/")) {
            return extractBrowserVersion(userAgent, "Firefox/", "Firefox");
        }

        // Safari (Chrome, Edge가 아닌 경우만)
        if (userAgent.contains("Safari/") && userAgent.contains("Version/")) {
            return extractBrowserVersion(userAgent, "Version/", "Safari");
        }

        // Opera
        if (userAgent.contains("OPR/")) {
            return extractBrowserVersion(userAgent, "OPR/", "Opera");
        }

        return null;
    }

    /**
     * AI Native v11.0: User-Agent에서 브라우저 버전 추출 (메이저 버전만)
     */
    private String extractBrowserVersion(String userAgent, String prefix, String browserName) {
        int idx = userAgent.indexOf(prefix);
        if (idx == -1) return null;

        int start = idx + prefix.length();
        if (start >= userAgent.length()) return null;

        int end = start;
        while (end < userAgent.length()) {
            char c = userAgent.charAt(end);
            if (c == '.' || c == ' ' || !Character.isDigit(c)) {
                break;
            }
            end++;
        }

        if (end == start) return null;

        String version = userAgent.substring(start, end);
        return browserName + "/" + version;
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

        // fallback: 기존 로직 (마지막 } 사용)
        endIndex = response.lastIndexOf('}');
        if (endIndex > startIndex) {
            return response.substring(startIndex, endIndex + 1);
        }

        return response;
    }
}