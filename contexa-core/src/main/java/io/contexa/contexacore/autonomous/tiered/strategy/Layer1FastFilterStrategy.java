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
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

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

    private final EmbeddingModel embeddingModel;
    private final RedisTemplate<String, Object> redisTemplate;
    private final UnifiedLLMOrchestrator llmOrchestrator;
    private final SecurityEventEnricher eventEnricher;
    private final Layer1PromptTemplate promptTemplate;
    private final FeedbackIntegrationProperties localFeedbackProperties;
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

    @Value("${spring.ai.security.tiered.layer1.embedding-similarity-threshold:0.85}")
    private double embeddingSimilarityThreshold;

    @Value("${spring.ai.security.tiered.layer1.embedding-search-limit:5}")
    private int embeddingSearchLimit;

    @Value("${spring.ai.security.tiered.layer1.embedding-cache-enabled:true}")
    private boolean embeddingCacheEnabled;

    @Autowired
    public Layer1FastFilterStrategy(@Autowired(required = false) UnifiedLLMOrchestrator llmOrchestrator,
                                    @Autowired(required = false) EmbeddingModel embeddingModel,
                                    @Autowired(required = false) UnifiedVectorService unifiedVectorService,
                                    @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                                    @Autowired(required = false) SecurityEventEnricher eventEnricher,
                                    @Autowired Layer1PromptTemplate promptTemplate,
                                    @Autowired FeedbackIntegrationProperties feedbackProperties,
                                    @Autowired(required = false) HCADVectorIntegrationService hcadVectorService,
                                    @Autowired(required = false) BaselineLearningService baselineLearningService) {
        this.llmOrchestrator = llmOrchestrator;
        this.embeddingModel = embeddingModel;
        this.unifiedVectorService = unifiedVectorService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate;
        this.localFeedbackProperties = feedbackProperties;
        this.baselineLearningService = baselineLearningService;
        // AbstractTieredStrategy의 protected 필드 설정
        this.feedbackProperties = feedbackProperties;
        this.hcadVectorService = hcadVectorService;

        log.info("Layer 1 Fast Filter Strategy initialized with Layer1PromptTemplate");
        log.info("  - Model: {}", modelName);
        log.info("  - Timeout: {}ms", timeoutMs);
        log.info("  - Cache TTL: {}s", cacheTtlSeconds);
        log.info("  - Embedding Similarity Threshold: {}", embeddingSimilarityThreshold);
        log.info("  - UnifiedVectorService available: {}", unifiedVectorService != null);
        log.info("  - BaselineLearningService available: {}", baselineLearningService != null);
    }

    /**
     * ThreatEvaluationStrategy 인터페이스 구현
     * ColdPathEventProcessor에서 전략으로 사용됨
     *
     * AI Native 전환:
     * - LLM이 ESCALATE 반환 시 shouldEscalate = true
     * - LLM이 threatLevel을 직접 결정 (규칙 기반 매핑 제거)
     */
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.info("Layer 1 Fast Filter Strategy evaluating event: {}", event.getEventId());

        SecurityDecision decision = analyzeEvent(event);

        // AI Native: LLM이 ESCALATE 액션을 반환하면 shouldEscalate = true
        boolean shouldEscalate = decision.getAction() == SecurityDecision.Action.ESCALATE;

        // AI Native: LLM이 결정한 action을 그대로 사용
        String action = decision.getAction() != null ? decision.getAction().name() : "ESCALATE";

        return ThreatAssessment.builder()
                .riskScore(decision.getRiskScore())
                .confidence(decision.getConfidence())
                // AI Native: LLM이 threatLevel을 직접 결정하도록 수정 필요
                // 현재는 임시로 null 설정 (Layer1PromptTemplate에서 threatLevel 반환하도록 수정 필요)
                .threatLevel(null)
                .indicators(new ArrayList<>())
                .recommendedActions(List.of(mapActionToRecommendation(decision.getAction())))
                .strategyName("Layer1-FastFilter")
                .assessedAt(LocalDateTime.now())
                .shouldEscalate(shouldEscalate)
                .action(action)  // AI Native: LLM action 직접 저장
                .build();
    }

    /**
     * 보안 이벤트 분석 (동기)
     *
     * @param event 보안 이벤트
     * @return 보안 결정
     */
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

            // 2. 임베딩 기반 유사도 검사 (AI Native: 고정 임계값 사용)
            if (embeddingModel != null) {
                SecurityDecision similarDecision = checkSimilarEvents(event);
                if (similarDecision != null && similarDecision.getEmbeddingSimilarity() > embeddingSimilarityThreshold) {
                    log.debug("Similar event found with similarity {} (threshold: {})",
                        similarDecision.getEmbeddingSimilarity(), embeddingSimilarityThreshold);
                    return similarDecision;
                }
            }

            // 3. LLM 분석 - Layer1PromptTemplate 사용 (AI Native: Baseline 컨텍스트 포함)
            String knownPatterns = getKnownPatterns(event);
            String userId = event.getUserId();

            // AI Native: 사용자 baseline 컨텍스트 및 편차 분석
            String baselineContext = null;
            String deviationAnalysis = null;
            if (baselineLearningService != null && userId != null) {
                baselineContext = baselineLearningService.buildBaselinePromptContext(userId, event);
                deviationAnalysis = baselineLearningService.analyzeDeviations(userId, event);
                log.debug("[Layer1] Baseline context generated for user {}: deviation={}",
                    userId, baselineLearningService.calculateDeviationScore(userId, event));
            }

            String promptText = promptTemplate.buildPrompt(event, knownPatterns, baselineContext, deviationAnalysis);

            ExecutionContext context = ExecutionContext.builder()
                    .prompt(new Prompt(promptText))
                    .tier(1)
                    .preferredModel(modelName)
                    .securityTaskType(ExecutionContext.SecurityTaskType.THREAT_FILTERING)
                    .timeoutMs((int)timeoutMs)
                    .requestId(event.getEventId())
                    .build();

            // AI Native: onErrorResume에서 규칙 기반 기본값 제거
            // riskScore/confidence를 null로 반환하여 NaN 처리
            String jsonResponse = llmOrchestrator.execute(context)
                    .timeout(Duration.ofMillis(timeoutMs))
                    .onErrorResume(Exception.class, e -> {
                        log.warn("[Layer1][AI Native] LLM execution failed, escalating to Layer 2: {}", event.getEventId(), e);
                        return reactor.core.publisher.Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"ESCALATE\",\"reasoning\":\"[AI Native] LLM execution failed - escalating to Layer 2\"}");
                    })
                    .block();

            Layer1SecurityResponse response = parseJsonResponse(jsonResponse);

            // 4. 응답을 SecurityDecision 으로 변환
            SecurityDecision decision = convertToSecurityDecision(response, event);
            decision.setAnalysisTime(startTime);
            decision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            decision.setProcessingLayer(1);
            decision.setLlmModel(modelName);

            // 5. 캐시 저장
            cacheDecision(cacheKey, decision);

            // 5-1. VectorStore에 저장 (향후 유사 이벤트 검색용)
            storeDecisionInVectorStore(event, decision);

            // 5-2. Cold→Hot 동기화 (riskScore >= 0.7)
            feedbackToHotPath(event, decision);

            // 6. 처리 시간 검증
            if (decision.getProcessingTimeMs() > timeoutMs) {
                log.warn("Layer 1 processing took {}ms, exceeding timeout of {}ms",
                        decision.getProcessingTimeMs(), timeoutMs);
            }

            return decision;

        } catch (Exception e) {
            log.error("Layer 1 analysis failed for event {}", event.getEventId(), e);
            // 실패 시 안전한 기본값 반환 (에스컬레이션)
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

        // 1. RAG 기반 위협 패턴 검색 (우선순위)
        if (unifiedVectorService != null) {
            try {
                String searchQuery = buildThreatSearchQuery(event);

                SearchRequest searchRequest = SearchRequest.builder()
                    .query(searchQuery)
                    .topK(5)  // 상위 5개 유사 위협 패턴
                    .similarityThreshold(0.7)
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

        // 2. Layer3 학습 패턴 조회 (기존 로직)
        if (redisTemplate != null) {
            try {
                String patternKey = localFeedbackProperties.getRedis().getPatternKeyPrefix() +
                        (event.getEventType() != null ? event.getEventType().toString() : FeedbackConstants.DEFAULT_EVENT_TYPE);
                int maxPatterns = localFeedbackProperties.getPattern().getMaxRecentPatterns();
                List<Object> layer3Patterns = redisTemplate.opsForList().range(patternKey, -maxPatterns, -1);

                if (layer3Patterns != null && !layer3Patterns.isEmpty()) {
                    for (Object pattern : layer3Patterns) {
                        Map<String, Object> feedback = (Map<String, Object>) pattern;

                        Double riskScore = (Double) feedback.get("riskScore");
                        // AI Native: 모든 패턴을 LLM에 전달 (임계값 필터링 제거)
                        if (riskScore != null) {
                            String threatCategory = (String) feedback.get("threatCategory");
                            if (threatCategory != null && !threatCategory.isBlank()) {
                                if (!patterns.isEmpty()) {
                                    patterns.append(", ");
                                }
                                patterns.append(String.format("%s(risk:%.1f)", threatCategory, riskScore));
                            }
                        }
                    }
                    log.debug("Layer3 patterns found for eventType={}: {}", event.getEventType(), patterns);
                }

            } catch (Exception e) {
                log.debug("Failed to retrieve Layer3 patterns", e);
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

    /**
     * Layer1SecurityResponse를 SecurityDecision으로 변환
     *
     * AI Native 전환:
     * - 기본값 할당 규칙 제거
     * - LLM 응답을 그대로 사용
     */
    private SecurityDecision convertToSecurityDecision(Layer1SecurityResponse response, SecurityEvent event) {
        try {
            SecurityDecision.Action decisionAction = mapToAction(response.getAction());

            // AI Native: 기본값 할당 제거 - LLM 응답 그대로 사용
            return SecurityDecision.builder()
                    .action(decisionAction)
                    .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
                    .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                    .matchedPattern(response.getMatchedPattern())
                    .knownThreat(response.getKnownThreat() != null && response.getKnownThreat())
                    .embeddingSimilarity(response.getEmbeddingSimilarity())
                    .reasoning(response.getReasoning() != null ? response.getReasoning() : "Layer 1 fast filter analysis")
                    .eventId(event.getEventId())
                    .build();

        } catch (Exception e) {
            log.error("Failed to convert Layer1SecurityResponse to SecurityDecision", e);
            return createEscalationDecision(event, System.currentTimeMillis());
        }
    }

    /**
     * AI 응답 검증
     *
     * AI Native 전환:
     * - LLM 응답 가공 완전 제거
     * - confidence 강제 상향 제거
     * - riskScore 기본값 할당 제거
     * - LLM이 반환한 값을 그대로 사용
     */
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

    /**
     * JSON 응답 파싱 (축약 JSON 우선, Jackson 폴백)
     *
     * 축약 형식: {"r":0.75,"c":0.85,"a":"E","d":"new IP from US"}
     * 기존 형식: {"riskScore":0.75,"confidence":0.85,"action":"ESCALATE","reasoning":"..."}
     *
     * @param jsonResponse LLM이 생성한 JSON 문자열
     * @return Layer1SecurityResponse 객체
     */
    private Layer1SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            // JSON 문자열에서 {}만 추출 (LLM이 추가 텍스트를 포함할 수 있음)
            String cleanedJson = extractJsonObject(jsonResponse);

            // 1단계: 축약 JSON 파싱 우선 시도 (프롬프트 최적화 후 표준 형식)
            Layer1SecurityResponse compactResponse = Layer1SecurityResponse.fromCompactJson(cleanedJson);
            if (compactResponse != null && isValidResponse(compactResponse)) {
                log.debug("Layer1 compact JSON parsing successful: {}", cleanedJson);
                return validateAndFixResponse(compactResponse);
            }

            // 2단계: 기존 전체 필드명 Jackson 파싱 (하위 호환성)
            log.debug("Layer1 compact parsing failed, falling back to Jackson: {}", cleanedJson);
            JsonNode jsonNode = objectMapper.readTree(cleanedJson);

            // AI Native: 필수 필드 추출 (기본값 할당 제거)
            // LLM이 반환하지 않은 필드는 null로 설정, validateAndFixResponse()에서 NaN 처리
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
            return createDefaultResponse();
        }
    }

    /**
     * Response 객체 유효성 검사
     * riskScore 또는 confidence가 설정되어 있으면 유효한 응답으로 판단
     */
    private boolean isValidResponse(Layer1SecurityResponse response) {
        if (response == null) return false;
        return response.getRiskScore() != null || response.getConfidence() != null;
    }

    /**
     * JSON 객체 추출 (LLM이 추가 텍스트를 포함할 수 있어서 {} 부분만 추출)
     */
    private String extractJsonObject(String text) {
        if (text == null || text.isEmpty()) {
            return "{}";
        }

        int start = text.indexOf('{');
        int end = text.lastIndexOf('}');

        if (start >= 0 && end > start) {
            return text.substring(start, end + 1);
        }

        // JSON 형식이 없으면 빈 객체 반환
        log.warn("No JSON object found in LLM response, using default: {}", text);
        return "{}";
    }

    /**
     * 기본 응답 생성 (오류 시)
     *
     * AI Native 전환:
     * - 규칙 기반 기본값 제거
     * - LLM 분석 실패 시 NaN으로 설정하여 명시
     */
    private Layer1SecurityResponse createDefaultResponse() {
        return Layer1SecurityResponse.builder()
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .category(null)
                .action("ESCALATE")
                .reasoning("Layer 1 analysis failed, escalating to Layer 2")
                .knownThreat(false)
                .build();
    }

    /**
     * 액션 매핑
     */
    private SecurityDecision.Action mapToAction(String action) {
        return switch (action.toUpperCase()) {
            case "ALLOW" -> SecurityDecision.Action.ALLOW;
            case "BLOCK" -> SecurityDecision.Action.BLOCK;
            case "MONITOR" -> SecurityDecision.Action.MONITOR;
            case "MITIGATE" -> SecurityDecision.Action.MITIGATE;
            default -> SecurityDecision.Action.ESCALATE;
        };
    }

    /**
     * 캐시 키 생성
     */
    private String generateCacheKey(SecurityEvent event) {
        String targetResource = eventEnricher.getTargetResource(event).orElse(FeedbackConstants.DEFAULT_USER_ID);
        String httpMethod = eventEnricher.getHttpMethod(event).orElse("GET");

        return String.format("layer1:decision:%s:%s:%s",
                event.getSourceIp() != null ? event.getSourceIp() : FeedbackConstants.DEFAULT_USER_ID,
                targetResource,
                httpMethod
        );
    }

    /**
     * 캐시된 결정 조회
     */
    private SecurityDecision getCachedDecision(String cacheKey) {
        if (redisTemplate == null) return null;

        try {
            return (SecurityDecision) redisTemplate.opsForValue().get(cacheKey);
        } catch (Exception e) {
            log.debug("Cache retrieval failed", e);
            return null;
        }
    }

    /**
     * 결정 캐시 저장
     */
    private void cacheDecision(String cacheKey, SecurityDecision decision) {
        if (redisTemplate == null) return;

        try {
            redisTemplate.opsForValue().set(cacheKey, decision, Duration.ofSeconds(cacheTtlSeconds));
        } catch (Exception e) {
            log.debug("Cache storage failed", e);
        }
    }

    /**
     * 유사 이벤트 확인 (임베딩 기반 벡터 검색)
     *
     * VectorStoreCacheLayer를 사용하여 과거 유사 이벤트를 검색하고,
     * 임계값 이상의 유사도를 가진 경우 해당 이벤트의 결정을 재사용합니다.
     */
    private SecurityDecision checkSimilarEvents(SecurityEvent event) {
        if (embeddingModel == null || unifiedVectorService == null) {
            log.trace("Embedding model or UnifiedVectorService not available, skipping similarity check");
            return null;
        }

        try {
            // 1. 이벤트 텍스트 요약 생성
            String eventText = eventEnricher.generateEventSummary(event);

            // 2. 임베딩 생성
            EmbeddingResponse embeddingResponse = embeddingModel.embedForResponse(List.of(eventText));
            if (embeddingResponse == null || embeddingResponse.getResults().isEmpty()) {
                log.debug("Failed to generate embedding for event {}", event.getEventId());
                return null;
            }

            // 3. UnifiedVectorService 에서 유사 이벤트 검색 (캐시 레이어 자동 적용)
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(eventText)
                    .topK(embeddingSearchLimit)
                    .similarityThreshold(embeddingSimilarityThreshold)
                    .build();

            List<Document> similarDocuments = unifiedVectorService.searchSimilar(searchRequest);

            if (similarDocuments.isEmpty()) {
                log.trace("No similar events found above threshold {} for event {}",
                        embeddingSimilarityThreshold, event.getEventId());
                return null;
            }

            // 4. 가장 유사한 문서에서 SecurityDecision 복원
            Document mostSimilar = similarDocuments.get(0);
            Double similarity = mostSimilar.getMetadata().get("similarity") != null
                    ? ((Number) mostSimilar.getMetadata().get("similarity")).doubleValue()
                    : null;

            // 5. 메타데이터에서 저장된 결정 정보 추출
            Map<String, Object> metadata = mostSimilar.getMetadata();
            if (!metadata.containsKey("riskScore") || !metadata.containsKey("action")) {
                log.debug("Similar document found but missing decision metadata for event {}", event.getEventId());
                return null;
            }

            // 6. SecurityDecision 재구성
            Double riskScore = ((Number) metadata.get("riskScore")).doubleValue();
            Double confidence = metadata.containsKey("confidence")
                    ? ((Number) metadata.get("confidence")).doubleValue()
                    : 0.8;
            String action = (String) metadata.get("action");
            String reasoning = metadata.containsKey("reasoning")
                    ? (String) metadata.get("reasoning")
                    : "Similar event detected";
            String matchedPattern = metadata.containsKey("matchedPattern")
                    ? (String) metadata.get("matchedPattern")
                    : null;
            Boolean knownThreat = metadata.containsKey("knownThreat")
                    ? (Boolean) metadata.get("knownThreat")
                    : false;

            SecurityDecision decision = SecurityDecision.builder()
                    .action(mapToAction(action))
                    .riskScore(riskScore)
                    .confidence(confidence)
                    .embeddingSimilarity(similarity)
                    .matchedPattern(matchedPattern)
                    .knownThreat(knownThreat)
                    .reasoning(String.format("Reused from similar event (similarity: %.2f): %s", similarity, reasoning))
                    .eventId(event.getEventId())
                    .analysisTime(System.currentTimeMillis())
                    .processingLayer(1)
                    .build();

            log.info("Found similar event with similarity {} for event {}, reusing decision: {}",
                    similarity, event.getEventId(), decision.getAction());

            // 7. (Optional) 캐시에도 저장
            if (embeddingCacheEnabled && redisTemplate != null) {
                String cacheKey = generateCacheKey(event);
                cacheDecision(cacheKey, decision);
            }

            return decision;

        } catch (Exception e) {
            log.warn("Embedding similarity check failed for event {}", event.getEventId(), e);
            return null;
        }
    }

    /**
     * SecurityDecision을 VectorStore에 저장
     *
     * 향후 유사 이벤트 검색을 위해 이벤트와 결정을 벡터 DB에 저장합니다.
     * UnifiedVectorService를 통해 자동으로 적절한 서비스로 라우팅됩니다.
     */
    private void storeDecisionInVectorStore(SecurityEvent event, SecurityDecision decision) {
        if (unifiedVectorService == null || embeddingModel == null) {
            return;
        }

        try {
            // 이벤트 요약 생성
            String eventText = eventEnricher.generateEventSummary(event);

            // 메타데이터 구성
            Map<String, Object> metadata = new HashMap<>();

            // 필수 공통 metadata
            metadata.put("documentType", "behavior");
            metadata.put("eventId", event.getEventId());
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            metadata.put("userId", event.getUserId() != null ? event.getUserId() : "unknown");

            // SecurityEvent 정보
            metadata.put("eventType", event.getEventType() != null ? event.getEventType().toString() : FeedbackConstants.DEFAULT_EVENT_TYPE);
            metadata.put("sourceIp", event.getSourceIp());
            metadata.put("sessionId", event.getSessionId());

            // SecurityDecision 정보
            metadata.put("riskScore", decision.getRiskScore());
            metadata.put("confidence", decision.getConfidence());
            metadata.put("action", decision.getAction().toString());
            metadata.put("reasoning", decision.getReasoning());
            metadata.put("matchedPattern", decision.getMatchedPattern());
            metadata.put("knownThreat", decision.isKnownThreat());
            metadata.put("processingLayer", decision.getProcessingLayer());
            metadata.put("threatCategory", decision.getThreatCategory() != null ? decision.getThreatCategory() : "UNKNOWN");

            // Layer3 ThreatIntelligence용
            if (decision.getRiskScore() >= 0.7 || decision.isKnownThreat()) {
                metadata.put("threatActor", "SUSPICIOUS-" + (event.getSourceIp() != null ? event.getSourceIp().replace(".", "-") : "UNKNOWN"));
                metadata.put("campaignId", "AUTO-" + java.util.UUID.randomUUID().toString().substring(0, 8));
                metadata.put("campaignName", "Automated Threat Detection");
                metadata.put("incidentId", "INC-" + java.util.UUID.randomUUID().toString().substring(0, 8));
                metadata.put("mitreTactic", "TA0043-Reconnaissance");
                metadata.put("assetCriticality", "HIGH");
                metadata.put("iocIndicator", decision.getMatchedPattern() != null ? decision.getMatchedPattern() : "fast_filter_detection");
            } else {
                metadata.put("threatActor", "NONE");
                metadata.put("campaignId", "NONE");
                metadata.put("campaignName", "");
                metadata.put("incidentId", "");
                metadata.put("mitreTactic", "");
                metadata.put("assetCriticality", "LOW");
                metadata.put("iocIndicator", "");
            }

            // Document 생성 및 저장 (UnifiedVectorService를 통한 자동 라우팅)
            Document document = new Document(eventText, metadata);
            unifiedVectorService.storeDocument(document);

            // Phase 1: 고위험 이벤트는 별도로 threat 문서 저장
            if (decision.getRiskScore() >= 0.7 || decision.isKnownThreat()) {
                storeThreatDocument(event, decision, eventText);
            }

            log.debug("Stored decision for event {} in VectorStore via UnifiedVectorService for future similarity search", event.getEventId());

        } catch (Exception e) {
            log.debug("Failed to store decision in VectorStore for event {}", event.getEventId(), e);
        }
    }

    /**
     * Layer1 고위험 이벤트를 위협 패턴으로 저장
     *
     * @param event 보안 이벤트
     * @param decision 보안 결정
     * @param eventText 이벤트 텍스트
     */
    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, String eventText) {
        try {
            Map<String, Object> threatMetadata = new HashMap<>();

            // 위협 전용 documentType (Enum 사용)
            threatMetadata.put("documentType", VectorDocumentType.THREAT.getValue());
            threatMetadata.put("threatConfirmed", decision.isKnownThreat());
            threatMetadata.put("riskScore", decision.getRiskScore());
            threatMetadata.put("behaviorAnomalyScore", decision.getRiskScore());

            // 기본 정보
            threatMetadata.put("eventId", event.getEventId());
            threatMetadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            threatMetadata.put("userId", event.getUserId() != null ? event.getUserId() : "unknown");
            threatMetadata.put("eventType", event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN");
            threatMetadata.put("sourceIp", event.getSourceIp());
            threatMetadata.put("sessionId", event.getSessionId());

            // 위협 분류
            threatMetadata.put("threatType", determineThreatType(decision));
            threatMetadata.put("threatCategory", decision.getThreatCategory() != null ? decision.getThreatCategory() : "UNKNOWN");
            threatMetadata.put("riskCategory", decision.getRiskScore() >= 0.9 ? "CRITICAL" : "HIGH");

            // MITRE ATT&CK
            threatMetadata.put("mitreTactic", "TA0043:Reconnaissance");
            threatMetadata.put("patternType", decision.getMatchedPattern() != null ? "known_pattern" : "anomaly_detected");

            // Layer 정보
            threatMetadata.put("processingLayer", "Layer1");
            threatMetadata.put("confidence", decision.getConfidence());
            threatMetadata.put("action", decision.getAction().toString());

            // IOC 지표
            if (decision.getMatchedPattern() != null) {
                threatMetadata.put("iocIndicators", "pattern:" + decision.getMatchedPattern());
            }

            // 위협 설명
            String threatDescription = String.format(
                "Layer1 Fast Filter Threat: User=%s, EventType=%s, IP=%s, RiskScore=%.2f, " +
                "ThreatCategory=%s, Pattern=%s, Action=%s",
                event.getUserId(),
                event.getEventType(),
                event.getSourceIp(),
                decision.getRiskScore(),
                decision.getThreatCategory(),
                decision.getMatchedPattern(),
                decision.getAction()
            );

            Document threatDoc = new Document(threatDescription, threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

            log.info("[Layer1] 위협 패턴 저장 완료: userId={}, riskScore={}, threatType={}",
                event.getUserId(), decision.getRiskScore(), threatMetadata.get("threatType"));

        } catch (Exception e) {
            log.warn("[Layer1] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }

    /**
     * 위협 유형 결정
     *
     * AI Native 전환:
     * - 패턴 매칭 기반 분류 규칙 완전 제거
     * - LLM이 threatType을 직접 결정하도록 위임
     * - 여기서는 LLM 응답에서 threatCategory를 그대로 반환
     */
    private String determineThreatType(SecurityDecision decision) {
        // AI Native: 패턴 매칭 규칙 완전 제거
        // LLM이 threatCategory를 직접 결정하므로 그대로 반환
        if (decision.getThreatCategory() != null && !decision.getThreatCategory().isBlank()) {
            return decision.getThreatCategory();
        }

        // AI Native: LLM이 threatCategory를 반환하지 않은 경우 null 반환
        // 규칙 기반 기본값 할당 제거
        return null;
    }

    /**
     * 에스컬레이션 결정 생성
     *
     * AI Native 전환:
     * - 규칙 기반 기본값 제거
     * - LLM 분석 실패 시 NaN으로 설정하여 명시
     */
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

    /**
     * 헬스 체크
     */
    public boolean isHealthy() {
        if (llmOrchestrator == null) {
            log.warn("Layer 1 health check: UnifiedLLMOrchestrator is not available");
            return false;
        }

        try {
            ExecutionContext healthContext = ExecutionContext.builder()
                    .prompt(new Prompt("Health check"))
                    .tier(1)
                    .securityTaskType(ExecutionContext.SecurityTaskType.QUICK_DETECTION)
                    .timeoutMs(5000)
                    .build();

            llmOrchestrator.execute(healthContext).block();
            return true;
        } catch (Exception e) {
            log.error("Layer 1 health check failed", e);
            return false;
        }
    }



    @Override
    public String getStrategyName() {
        return "Layer1-FastFilter-Strategy";
    }

    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        return new ArrayList<>();
    }

    @Override
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        mapping.put("framework", "FAST_FILTER");
        mapping.put("tier", "1");
        return mapping;
    }

    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        actions.add("QUICK_DECISION");
        actions.add("CACHE_RESULT");
        return actions;
    }

    /**
     * AI Native: 규칙 기반 위험 점수 계산 제거
     * LLM이 riskScore를 직접 결정하므로 이 메서드는 NaN 반환
     */
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        // AI Native: 규칙 기반 계산 제거 - LLM이 riskScore 직접 결정
        return Double.NaN;
    }

    // AI Native 전환: mapRiskScoreToThreatLevel() 규칙 기반 매핑 제거
    // LLM이 threatLevel을 직접 결정하므로 이 메서드는 더 이상 사용하지 않음
    // 기존 참조는 null 반환으로 대체 (evaluate 메서드에서 직접 null 설정)

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