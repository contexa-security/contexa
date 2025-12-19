package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.config.FeedbackConstants;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.response.Layer1SecurityResponse;
import io.contexa.contexacore.autonomous.tiered.template.Layer1PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Layer 1: 초고속 필터링 전략
 *
 * TinyLlama와 같은 경량 LLM을 사용하여 빠른 의사결정을 수행합니다.
 * AI-Native 접근법으로 전통적인 규칙 기반 시스템을 대체합니다.
 */
@Slf4j

public class Layer1FastFilterStrategy extends AbstractTieredStrategy {

    private final RedisTemplate<String, Object> redisTemplate;
    private final UnifiedLLMOrchestrator llmOrchestrator;
    private final SecurityEventEnricher eventEnricher;
    private final Layer1PromptTemplate promptTemplate;
    private final UnifiedVectorService unifiedVectorService;
    private final BaselineLearningService baselineLearningService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // 프롬프트 템플릿

    @Value("${spring.ai.security.layer1.model:tinyllama}")
    private String modelName;

    @Value("${spring.ai.security.tiered.layer1.timeout-ms:3000}")
    private long timeoutMs;

    @Value("${spring.ai.security.tiered.layer1.cache-ttl-seconds:60}")
    private long cacheTtlSeconds;

    // Phase 7: RAG 파라미터 설정화 (AI Native - 하드코딩 제거)
    @Value("${spring.ai.security.tiered.layer1.rag.top-k:3}")
    private int ragTopK;

    @Value("${spring.ai.security.tiered.layer1.rag.similarity-threshold:0.8}")
    private double ragSimilarityThreshold;

    @Autowired
    public Layer1FastFilterStrategy(@Autowired(required = false) UnifiedLLMOrchestrator llmOrchestrator,
                                    @Autowired(required = false) UnifiedVectorService unifiedVectorService,
                                    @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                                    @Autowired(required = false) SecurityEventEnricher eventEnricher,
                                    @Autowired Layer1PromptTemplate promptTemplate,
                                    @Autowired FeedbackIntegrationProperties feedbackProperties,
                                    @Autowired(required = false) BaselineLearningService baselineLearningService) {
        this.llmOrchestrator = llmOrchestrator;
        this.unifiedVectorService = unifiedVectorService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate;
        this.baselineLearningService = baselineLearningService;

        log.info("Layer 1 Fast Filter Strategy initialized with Layer1PromptTemplate");
        log.info("  - Model: {}", modelName);
        log.info("  - Timeout: {}ms", timeoutMs);
        log.info("  - Cache TTL: {}s", cacheTtlSeconds);
        log.info("  - UnifiedVectorService available: {}", unifiedVectorService != null);
        log.info("  - BaselineLearningService available: {}", baselineLearningService != null);
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.info("Layer 1 Fast Filter Strategy evaluating event: {}", event.getEventId());

        SecurityDecision decision = analyzeEvent(event);
        boolean shouldEscalate = decision.getAction() == SecurityDecision.Action.ESCALATE;
        String action = decision.getAction() != null ? decision.getAction().name() : "ESCALATE";

        return ThreatAssessment.builder()
                .riskScore(decision.getRiskScore())
                .confidence(decision.getConfidence())
                .threatLevel(null)
                .indicators(new ArrayList<>())
                .recommendedActions(List.of(mapActionToRecommendation(decision.getAction())))
                .strategyName("Layer1-FastFilter")
                .shouldEscalate(shouldEscalate)
                .action(action)  // AI Native: LLM action 직접 저장
                .build();
    }

    public SecurityDecision analyzeEvent(SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            // 1. 캐시 확인
            String cacheKey = generateCacheKey(event);
            SecurityDecision cachedDecision = getCachedDecision(cacheKey);
            if (cachedDecision != null) {
                log.debug("Cache hit for event {}", event.getEventId());
                return cachedDecision;
            }

            String knownPatterns = getKnownPatterns(event);
            String userId = event.getUserId();
            String baselineContext = null;
            if (baselineLearningService != null && userId != null) {
                baselineContext = baselineLearningService.buildBaselinePromptContext(userId, event);
                log.debug("[Layer1] Baseline context generated for user {}", userId);
            }

            String promptText = promptTemplate.buildPrompt(event, knownPatterns, baselineContext);

            ExecutionContext context = ExecutionContext.builder()
                    .prompt(new Prompt(promptText))
                    .tier(1)
                    .preferredModel(modelName)
                    .securityTaskType(ExecutionContext.SecurityTaskType.THREAT_FILTERING)
                    .timeoutMs((int)timeoutMs)
                    .requestId(event.getEventId())
                    .build();

            String jsonResponse = llmOrchestrator.execute(context)
                    .timeout(Duration.ofMillis(timeoutMs))
                    .onErrorResume(Exception.class, e -> {
                        log.warn("[Layer1][AI Native] LLM execution failed, escalating to Layer 2: {}", event.getEventId(), e);
                        return reactor.core.publisher.Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"ESCALATE\",\"reasoning\":\"[AI Native] LLM execution failed - escalating to Layer 2\"}");
                    })
                    .block();

            Layer1SecurityResponse response = parseJsonResponse(jsonResponse);

            SecurityDecision decision = convertToSecurityDecision(response, event);
            decision.setAnalysisTime(startTime);
            decision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            decision.setProcessingLayer(1);
            decision.setLlmModel(modelName);

            cacheDecision(cacheKey, decision);

            storeDecisionInVectorStore(event, decision);

            if (decision.getProcessingTimeMs() > timeoutMs) {
                log.warn("Layer 1 processing took {}ms, exceeding timeout of {}ms",
                        decision.getProcessingTimeMs(), timeoutMs);
            }

            return decision;

        } catch (Exception e) {
            log.error("Layer 1 analysis failed for event {}", event.getEventId(), e);
            return createEscalationDecision(event, startTime);
        }
    }

    /**
     * 비동기 분석
     */
    public CompletableFuture<SecurityDecision> analyzeEventAsync(SecurityEvent event) {
        return CompletableFuture.supplyAsync(() -> analyzeEvent(event))
                .orTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .exceptionally(throwable -> {
                    log.error("Layer 1 async analysis failed or timed out", throwable);
                    return createEscalationDecision(event, System.currentTimeMillis());
                });
    }


    /**
     * Phase 5.3: Layer3 학습 패턴 + RAG 기반 위협 패턴 조회
     */
    private String getKnownPatterns(SecurityEvent event) {
        StringBuilder patterns = new StringBuilder();

        if (unifiedVectorService != null) {
            try {
                String searchQuery = buildThreatSearchQuery(event);

                // Phase 7: 하드코딩 제거 → 설정 주입
                SearchRequest searchRequest = SearchRequest.builder()
                    .query(searchQuery)
                    .topK(ragTopK)
                    .similarityThreshold(ragSimilarityThreshold)
                    .build();

                List<Document> threatDocs = unifiedVectorService.searchSimilar(searchRequest);

                if (threatDocs != null && !threatDocs.isEmpty()) {
                    for (Document doc : threatDocs) {
                        String threatInfo = extractThreatInfo(doc);
                        if (threatInfo != null && !threatInfo.isBlank()) {
                            if (!patterns.isEmpty()) {
                                patterns.append(", ");
                            }
                            patterns.append(threatInfo);
                        }
                    }
                    log.debug("RAG threat patterns found: {} docs for event {}",
                        threatDocs.size(), event.getEventId());
                }
            } catch (Exception e) {
                log.warn("Failed to retrieve RAG threat patterns: {}", e.getMessage());
            }
        }

        return patterns.isEmpty() ? "none" : patterns.toString();
    }

    /**
     * 이벤트 기반 위협 검색 쿼리 생성
     */
    private String buildThreatSearchQuery(SecurityEvent event) {
        StringBuilder query = new StringBuilder();

        // 이벤트 타입 기반 쿼리
        if (event.getEventType() != null) {
            query.append(event.getEventType().toString()).append(" ");
        }

        // 위협 타입 추가
        if (event.getThreatType() != null && !event.getThreatType().isBlank()) {
            query.append(event.getThreatType()).append(" ");
        }

        // 소스 IP 기반 위협 검색
        if (event.getSourceIp() != null && !event.getSourceIp().equals("unknown")) {
            query.append("IP:").append(event.getSourceIp()).append(" ");
        }

        // 공격 벡터 추가
        if (event.getAttackVector() != null && !event.getAttackVector().isBlank()) {
            query.append(event.getAttackVector()).append(" ");
        }

        return query.toString().trim();
    }

    /**
     * Document에서 위협 정보 추출
     */
    private String extractThreatInfo(Document doc) {
        try {
            Map<String, Object> metadata = doc.getMetadata();
            String threatCategory = (String) metadata.get("threatCategory");
            Object riskScoreObj = metadata.get("riskScore");

            if (threatCategory != null && !threatCategory.isBlank()) {
                if (riskScoreObj instanceof Number) {
                    double riskScore = ((Number) riskScoreObj).doubleValue();
                    return String.format("%s(risk:%.1f,RAG)", threatCategory, riskScore);
                }
                return String.format("%s(RAG)", threatCategory);
            }

            // Metadata에 정보가 없으면 content에서 추출 시도
            String content = doc.getText();
            if (content != null && content.length() > 50) {
                return content.substring(0, 50) + "...(RAG)";
            }
        } catch (Exception e) {
            log.debug("Failed to extract threat info from document: {}", e.getMessage());
        }
        return null;
    }

    private SecurityDecision convertToSecurityDecision(Layer1SecurityResponse response, SecurityEvent event) {
        try {
            SecurityDecision.Action decisionAction = mapToAction(response.getAction());

            return SecurityDecision.builder()
                    .action(decisionAction)
                    .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
                    .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                    .reasoning(response.getReasoning() != null ? response.getReasoning() : "Layer 1 fast filter analysis")
                    .eventId(event.getEventId())
                    .build();

        } catch (Exception e) {
            log.error("Failed to convert Layer1SecurityResponse to SecurityDecision", e);
            return createEscalationDecision(event, System.currentTimeMillis());
        }
    }

    private Layer1SecurityResponse validateAndFixResponse(Layer1SecurityResponse response) {
        if (response == null) {
            log.warn("[Layer1][AI Native] LLM 응답 null - 에스컬레이션 필요");
            return Layer1SecurityResponse.builder()
                    .riskScore(Double.NaN)
                    .confidence(Double.NaN)
                    .action("ESCALATE")
                    .reasoning("LLM response was null")
                    .build();
        }

        // AI Native: LLM 응답 검증만 수행 (가공 없음)
        if (response.getConfidence() == null) {
            log.warn("[Layer1][AI Native] LLM이 confidence 미반환 (가공 없이 NaN 사용)");
            response.setConfidence(Double.NaN);
        }

        if (response.getRiskScore() == null) {
            log.warn("[Layer1][AI Native] LLM이 riskScore 미반환 (가공 없이 NaN 사용)");
            response.setRiskScore(Double.NaN);
        }

        return response;
    }

    private Layer1SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            // JSON 문자열에서 {}만 추출 (LLM이 추가 텍스트를 포함할 수 있음)
            String cleanedJson = extractJsonObject(jsonResponse);

            Layer1SecurityResponse compactResponse = Layer1SecurityResponse.fromCompactJson(cleanedJson);
            if (isValidResponse(compactResponse)) {
                log.debug("Layer1 compact JSON parsing successful: {}", cleanedJson);
                return validateAndFixResponse(compactResponse);
            }

            log.debug("Layer1 compact parsing failed, falling back to Jackson: {}", cleanedJson);
            JsonNode jsonNode = objectMapper.readTree(cleanedJson);

            Double riskScore = jsonNode.has("riskScore") && !jsonNode.get("riskScore").isNull()
                ? jsonNode.get("riskScore").asDouble() : null;
            Double confidence = jsonNode.has("confidence") && !jsonNode.get("confidence").isNull()
                ? jsonNode.get("confidence").asDouble() : null;
            String action = jsonNode.has("action") ? jsonNode.get("action").asText() : "ESCALATE";
            String reasoning = jsonNode.has("reasoning") ? jsonNode.get("reasoning").asText() : "No reasoning provided";

            // Response 객체 생성
            Layer1SecurityResponse response = Layer1SecurityResponse.builder()
                    .riskScore(riskScore)
                    .confidence(confidence)
                    .action(action)
                    .reasoning(reasoning)
                    .build();

            // 검증 및 수정
            return validateAndFixResponse(response);

        } catch (Exception e) {
            log.error("Failed to parse JSON response from Layer1 LLM: {}", jsonResponse, e);
            // AI Native: 파싱 실패 시 null을 validateAndFixResponse()에 전달하여 NaN/ESCALATE 처리
            return validateAndFixResponse(null);
        }
    }

    private boolean isValidResponse(Layer1SecurityResponse response) {
        if (response == null) return false;
        return response.getRiskScore() != null || response.getConfidence() != null;
    }

    private SecurityDecision.Action mapToAction(String action) {
        return switch (action.toUpperCase()) {
            case "ALLOW" -> SecurityDecision.Action.ALLOW;
            case "BLOCK" -> SecurityDecision.Action.BLOCK;
            case "MONITOR" -> SecurityDecision.Action.MONITOR;
            case "MITIGATE" -> SecurityDecision.Action.MITIGATE;
            default -> SecurityDecision.Action.ESCALATE;
        };
    }

    private String generateCacheKey(SecurityEvent event) {
        String targetResource = eventEnricher.getTargetResource(event).orElse(FeedbackConstants.DEFAULT_USER_ID);
        String httpMethod = eventEnricher.getHttpMethod(event).orElse("GET");

        return String.format("layer1:decision:%s:%s:%s",
                event.getSourceIp() != null ? event.getSourceIp() : FeedbackConstants.DEFAULT_USER_ID,
                targetResource,
                httpMethod
        );
    }

    private SecurityDecision getCachedDecision(String cacheKey) {
        if (redisTemplate == null) return null;

        try {
            return (SecurityDecision) redisTemplate.opsForValue().get(cacheKey);
        } catch (Exception e) {
            log.debug("Cache retrieval failed", e);
            return null;
        }
    }

    private void cacheDecision(String cacheKey, SecurityDecision decision) {
        if (redisTemplate == null) return;

        try {
            redisTemplate.opsForValue().set(cacheKey, decision, Duration.ofSeconds(cacheTtlSeconds));
        } catch (Exception e) {
            log.debug("Cache storage failed", e);
        }
    }

    private void storeDecisionInVectorStore(SecurityEvent event, SecurityDecision decision) {
        if (unifiedVectorService == null) {
            return;
        }

        try {
            String eventText = eventEnricher.generateEventSummary(event);
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("eventId", event.getEventId() != null ? event.getEventId() : "unknown");
            metadata.put("userId", event.getUserId() != null ? event.getUserId() : "unknown");
            metadata.put("sourceIp", event.getSourceIp() != null ? event.getSourceIp() : "unknown");
            metadata.put("action", decision.getAction() != null ? decision.getAction().toString() : "ESCALATE");
            double riskScore = decision.getRiskScore();
            metadata.put("riskScore", Double.isNaN(riskScore) ? -1.0 : riskScore);
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));

            // Document 생성 및 저장
            Document document = new Document(eventText, metadata);
            unifiedVectorService.storeDocument(document);

            log.debug("Stored decision for event {} in VectorStore (minimal metadata)", event.getEventId());

        } catch (Exception e) {
            log.debug("Failed to store decision in VectorStore for event {}", event.getEventId(), e);
        }
    }

    private SecurityDecision createEscalationDecision(SecurityEvent event, long startTime) {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ESCALATE)
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .analysisTime(startTime)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .processingLayer(1)
                .eventId(event.getEventId())
                .reasoning("Layer 1 analysis failed or uncertain, escalating to Layer 2")
                .build();
    }

    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        return List.of("QUICK_DECISION");  // AI Native: 단순화
    }

    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        return Double.NaN;  // AI Native: LLM이 riskScore 직접 결정
    }

    private String mapActionToRecommendation(SecurityDecision.Action action) {
        switch (action) {
            case BLOCK:
                return "BLOCK_IMMEDIATELY";
            case ALLOW:
                return "ALLOW";
            case ESCALATE:
                return "ESCALATE_TO_LAYER2";
            default:
                return "MONITOR";
        }
    }

    @Override
    protected String getLayerName() {
        return "Layer1";
    }
}