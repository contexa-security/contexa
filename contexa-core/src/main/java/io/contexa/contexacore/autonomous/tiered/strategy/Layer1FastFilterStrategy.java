package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.config.FeedbackConstants;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
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
    private final TieredStrategyProperties tieredStrategyProperties;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // 프롬프트 템플릿

    @Value("${spring.ai.security.layer1.model:tinyllama}")
    private String modelName;

    @Value("${spring.ai.security.tiered.layer1.timeout-ms:3000}")
    private long timeoutMs;

    @Value("${spring.ai.security.tiered.layer1.cache-ttl-seconds:60}")
    private long cacheTtlSeconds;

    // Phase 7: RAG 파라미터 설정화
    @Value("${spring.ai.security.tiered.layer1.rag.top-k:3}")
    private int ragTopK;
    // AI Native v3.3.0: ragSimilarityThreshold 제거 - LLM이 직접 관련성 판단

    @Autowired
    public Layer1FastFilterStrategy(@Autowired(required = false) UnifiedLLMOrchestrator llmOrchestrator,
                                    @Autowired(required = false) UnifiedVectorService unifiedVectorService,
                                    @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                                    @Autowired(required = false) SecurityEventEnricher eventEnricher,
                                    @Autowired Layer1PromptTemplate promptTemplate,
                                    @Autowired(required = false) BaselineLearningService baselineLearningService,
                                    @Autowired TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.unifiedVectorService = unifiedVectorService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate;
        this.baselineLearningService = baselineLearningService;
        this.tieredStrategyProperties = tieredStrategyProperties;

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

                // AI Native v3.3.0: similarityThreshold 제거 - LLM이 직접 관련성 판단
                SearchRequest searchRequest = SearchRequest.builder()
                    .query(searchQuery)
                    .topK(ragTopK)
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

        // AI Native: 기본값 "none" 제거 - 빈 문자열 반환, LLM이 직접 인식
        return patterns.toString();
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

        // AI Native: deprecated getThreatType() 제거
        // ThreatAssessment에서 위협 유형 관리

        // 소스 IP 기반 위협 검색
        if (event.getSourceIp() != null && !event.getSourceIp().equals("unknown")) {
            query.append("IP:").append(event.getSourceIp()).append(" ");
        }

        // AI Native: deprecated getAttackVector() 제거
        // 공격 벡터 정보는 metadata 또는 ThreatAssessment에서 관리

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

    /**
     * LLM 응답 검증 (AI Native - Action 기반 Zero Trust)
     *
     * Zero Trust 원칙:
     * - 점수 기반이 아닌 ACTION 기반 의사결정
     * - riskScore/confidence는 감사/모니터링용 메타데이터
     * - 유효한 action이 없으면 Fail-Safe로 ESCALATE
     *
     * 검증 항목:
     * 1. [필수] action 유효성 - null/empty/invalid -> ESCALATE
     * 2. [경고] riskScore 범위 - 0.0~1.0 벗어나면 로그 경고
     * 3. [경고] confidence 범위 - 0.0~1.0 벗어나면 로그 경고
     * 4. [경고] 데이터 일관성 - 모순 감지 시 로그 경고
     */
    private Layer1SecurityResponse validateAndFixResponse(Layer1SecurityResponse response) {
        if (response == null) {
            log.warn("[Layer1][AI Native] LLM 응답 null - Fail-Safe ESCALATE 적용");
            return Layer1SecurityResponse.builder()
                    .riskScore(Double.NaN)
                    .confidence(Double.NaN)
                    .action("ESCALATE")
                    .reasoning("[AI Native] LLM response was null - Fail-Safe escalation")
                    .build();
        }

        // 1. [필수] Action 검증 - Zero Trust 핵심
        String action = response.getAction();
        if (!isValidAction(action)) {
            log.warn("[Layer1][AI Native] 유효하지 않은 action '{}' - Fail-Safe ESCALATE 적용", action);
            response.setAction("ESCALATE");
            response.setReasoning(
                (response.getReasoning() != null ? response.getReasoning() + " | " : "") +
                "[AI Native] Invalid action detected - Fail-Safe escalation"
            );
        }

        // 2. [경고] riskScore 범위 검증 (감사용 메타데이터 - 값 변경 안함)
        Double riskScore = response.getRiskScore();
        if (riskScore == null) {
            log.debug("[Layer1][AI Native] LLM이 riskScore 미반환 (감사용 NaN 설정)");
            response.setRiskScore(Double.NaN);
        } else if (riskScore < 0.0 || riskScore > 1.0) {
            log.warn("[Layer1][AI Native] riskScore 범위 초과: {} (유효 범위: 0.0-1.0, 값 유지)", riskScore);
        }

        // 3. [경고] confidence 범위 검증 (감사용 메타데이터 - 값 변경 안함)
        Double confidence = response.getConfidence();
        if (confidence == null) {
            log.debug("[Layer1][AI Native] LLM이 confidence 미반환 (감사용 NaN 설정)");
            response.setConfidence(Double.NaN);
        } else if (confidence < 0.0 || confidence > 1.0) {
            log.warn("[Layer1][AI Native] confidence 범위 초과: {} (유효 범위: 0.0-1.0, 값 유지)", confidence);
        }

        // 4. [경고] 데이터 일관성 검증 - 모순 감지 (참고용 로그)
        validateDataConsistency(response);

        return response;
    }

    // isValidAction()은 AbstractTieredStrategy로 이동됨

    /**
     * 데이터 일관성 검증 (AI Native v3.3.0)
     *
     * AI Native: 점수 기반 임계값 분기 제거
     * LLM이 결정한 Action만 신뢰, 점수 기반 모순 감지 폐기
     */
    private void validateDataConsistency(Layer1SecurityResponse response) {
        // AI Native v3.3.0: 점수 기반 임계값 분기 제거
        // LLM이 결정한 Action만 신뢰
        if (response.getAction() == null || response.getAction().isBlank()) {
            log.debug("[Layer1][AI Native] Action이 없음 - ESCALATE 적용");
        }
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

    /**
     * 문자열 action을 SecurityDecision.Action으로 매핑
     * AbstractTieredStrategy의 mapStringToAction()으로 위임
     */
    private SecurityDecision.Action mapToAction(String action) {
        return mapStringToAction(action);
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
            // AI Native: null인 경우 필드 생략 (LLM이 "unknown"을 실제 값으로 오해 방지)
            if (event.getEventId() != null) {
                metadata.put("eventId", event.getEventId());
            }
            if (event.getUserId() != null) {
                metadata.put("userId", event.getUserId());
            }
            if (event.getSourceIp() != null) {
                metadata.put("sourceIp", event.getSourceIp());
            }
            metadata.put("action", decision.getAction() != null ? decision.getAction().toString() : "ESCALATE");
            // AI Native: NaN인 경우 해당 필드를 생략 (LLM이 -1.0을 낮은 위험도로 오해 방지)
            double riskScore = decision.getRiskScore();
            if (!Double.isNaN(riskScore)) {
                metadata.put("riskScore", riskScore);
            }
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

    /**
     * Action을 권장 조치 문자열로 변환 (AI Native v3.3.0 - 4개 Action)
     */
    private String mapActionToRecommendation(SecurityDecision.Action action) {
        return switch (action) {
            case ALLOW -> "ALLOW";
            case BLOCK -> "BLOCK_IMMEDIATELY";
            case CHALLENGE -> "REQUIRE_MFA";
            case ESCALATE -> "ESCALATE_TO_LAYER2";
        };
    }

    @Override
    protected String getLayerName() {
        return "Layer1";
    }
}