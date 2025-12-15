package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.response.Layer2SecurityResponse;
import io.contexa.contexacore.autonomous.tiered.template.Layer2PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
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
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Layer 2: 컨텍스트 기반 분석 전략
 *
 * Llama3.1:8b와 같은 중급 LLM을 사용하여 세션 컨텍스트와 행동 패턴을 분석합니다.
 * 사용자 행동, 시간적 패턴, 세션 이력을 고려한 정교한 분석을 수행합니다.
 */
@Slf4j

public class Layer2ContextualStrategy extends AbstractTieredStrategy {

    private final UnifiedLLMOrchestrator llmOrchestrator;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityEventEnricher eventEnricher;
    private final Layer2PromptTemplate promptTemplate;
    private final HCADVectorIntegrationService localHcadVectorService;
    private final BehaviorVectorService behaviorVectorService;
    private final UnifiedVectorService unifiedVectorService;
    private final BaselineLearningService baselineLearningService;
    private final Map<String, SessionContext> sessionContextCache = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();


    @Value("${ai.security.tiered.layer2.model:llama3.1:8b}")
    private String modelName;

    @Value("${ai.security.tiered.layer2.timeout-ms:30000}")
    private long timeoutMs;

    @Value("${ai.security.tiered.layer2.context-window-minutes:30}")
    private int contextWindowMinutes;

    @Value("${ai.security.tiered.layer2.vector-search-limit:10}")
    private int vectorSearchLimit;

    @Autowired
    public Layer2ContextualStrategy(@Autowired(required = false) UnifiedLLMOrchestrator llmOrchestrator,
                                    @Autowired(required = false) UnifiedVectorService unifiedVectorService,
                                    @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                                    @Autowired(required = false) SecurityEventEnricher eventEnricher,
                                    @Autowired(required = false) Layer2PromptTemplate promptTemplate,
                                    @Autowired(required = false) HCADVectorIntegrationService hcadVectorService,
                                    @Autowired(required = false) BehaviorVectorService behaviorVectorService,
                                    @Autowired FeedbackIntegrationProperties feedbackProperties,
                                    @Autowired(required = false) BaselineLearningService baselineLearningService) {
        this.llmOrchestrator = llmOrchestrator;
        this.unifiedVectorService = unifiedVectorService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate : new Layer2PromptTemplate(eventEnricher);
        this.localHcadVectorService = hcadVectorService;
        this.behaviorVectorService = behaviorVectorService;
        this.baselineLearningService = baselineLearningService;
        this.hcadVectorService = hcadVectorService;
        this.feedbackProperties = feedbackProperties;

        log.info("Layer 2 Contextual Strategy initialized with UnifiedLLMOrchestrator");
        log.info("  - Model: {}", modelName);
        log.info("  - Timeout: {}ms", timeoutMs);
        log.info("  - Context Window: {} minutes", contextWindowMinutes);
        log.info("  - UnifiedVectorService available: {}", unifiedVectorService != null);
        log.info("  - BaselineLearningService available: {}", baselineLearningService != null);
    }

    /**
     * ThreatEvaluationStrategy 인터페이스 구현
     * ColdPathEventProcessorRefactored에서 전략으로 사용됨
     *
     * AI Native 전환:
     * - LLM이 ESCALATE 반환 시 shouldEscalate = true
     * - LLM이 threatLevel을 직접 결정 (규칙 기반 매핑 제거)
     */
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.info("Layer 2 Contextual Strategy evaluating event: {}", event.getEventId());

        // Layer1 결정을 기본값으로 생성
        SecurityDecision layer1Decision = createDefaultDecision();

        // 컨텍스트 분석 실행
        SecurityDecision decision = analyzeWithContext(event, layer1Decision);

        // AI Native: LLM이 ESCALATE 액션을 반환하면 shouldEscalate = true
        boolean shouldEscalate = decision.getAction() == SecurityDecision.Action.ESCALATE;

        // SecurityDecision을 ThreatAssessment로 변환
        return ThreatAssessment.builder()
                .riskScore(decision.getRiskScore())
                .confidence(decision.getConfidence())
                // AI Native: LLM이 threatLevel을 직접 결정하도록 수정 필요
                .threatLevel(null)
                .indicators(new ArrayList<>())
                .recommendedActions(Arrays.asList(mapActionToRecommendation(decision.getAction())))
                .strategyName("Layer2-Contextual")
                .assessedAt(LocalDateTime.now())
                .shouldEscalate(shouldEscalate)
                .build();
    }

    /**
     * 컨텍스트를 포함한 이벤트 분석
     *
     * @param event 보안 이벤트
     * @param layer1Decision Layer 1의 결정
     * @return 향상된 보안 결정
     */
    public SecurityDecision analyzeWithContext(SecurityEvent event, SecurityDecision layer1Decision) {
        long startTime = System.currentTimeMillis();

        try {
            // 1. 세션 컨텍스트 수집
            SessionContext sessionContext = buildSessionContext(event);

            // 3. 행동 패턴 분석
            BehaviorAnalysis behaviorAnalysis = analyzeBehaviorPatterns(event, sessionContext);

            // 4. 벡터 스토어에서 관련 컨텍스트 검색
            List<Document> relatedDocuments = searchRelatedContext(event);

            // 4. PromptTemplate을 통한 프롬프트 구성
            Layer2PromptTemplate.SessionContext sessionCtx = convertToTemplateSessionContext(sessionContext);
            Layer2PromptTemplate.BehaviorAnalysis behaviorCtx = convertToTemplateBehaviorAnalysis(behaviorAnalysis);

            String promptText = promptTemplate.buildPrompt(event, layer1Decision, sessionCtx, behaviorCtx, relatedDocuments);

            // 5. LLM 분석 실행 - execute() + 수동 JSON 파싱
            // BeanOutputConverter 제거로 2500+ 토큰 → 500 토큰 (80% 감소!)
            // 예상 성능: 3-5초 → 100-300ms (15-50배 개선!)
            Layer2SecurityResponse response = null;
            if (llmOrchestrator != null) {
                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(promptText))
                        .tier(2)
                        .preferredModel(modelName)
                        .securityTaskType(ExecutionContext.SecurityTaskType.CONTEXTUAL_ANALYSIS)
                        .timeoutMs((int)timeoutMs)
                        .requestId(event.getEventId())
                        .build();

                // AI Native: onErrorResume에서 규칙 기반 기본값 제거
                // riskScore/confidence를 null로 반환하여 NaN 처리
                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(timeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.warn("[Layer2][AI Native] LLM execution failed, escalating to Layer 3: {}", event.getEventId(), e);
                            return Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"ESCALATE\",\"reasoning\":\"[AI Native] LLM execution failed - escalating to Layer 3\",\"threatCategory\":\"UNKNOWN\"}");
                        })
                        .block();

                response = parseJsonResponse(jsonResponse);
            } else {
                log.warn("UnifiedLLMOrchestrator not available for Layer 2 analysis");
                response = createDefaultResponse();
            }

            // 6. 응답을 SecurityDecision 으로 변환
            SecurityDecision decision = convertToSecurityDecision(response, event, layer1Decision);

            // 7. 메타데이터 추가
            enrichDecisionWithContext(decision, sessionContext, behaviorAnalysis);
            decision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            decision.setProcessingLayer(2);

            // 8. 세션 컨텍스트 업데이트
            updateSessionContext(event, decision);

            // 9. 벡터 스토어에 저장 (학습용)
            storeInVectorDatabase(event, decision);

            // 10. Cold→Hot 동기화 (riskScore >= 0.7)
            feedbackToHotPath(event, decision);

            log.info("Layer 2 analysis completed in {}ms - Risk: {}, Action: {}",
                    decision.getProcessingTimeMs(), decision.getRiskScore(), decision.getAction());

            return decision;

        } catch (Exception e) {
            log.error("Layer 2 analysis failed for event {}", event.getEventId(), e);
            return enhanceLayer1Decision(layer1Decision, startTime);
        }
    }

    /**
     * 비동기 컨텍스트 분석
     */
    public Mono<SecurityDecision> analyzeWithContextAsync(SecurityEvent event,
                                                          SecurityDecision layer1Decision) {
        return Mono.fromCallable(() -> analyzeWithContext(event, layer1Decision))
                .timeout(Duration.ofMillis(timeoutMs))
                .onErrorResume(throwable -> {
                    log.error("Layer 2 async analysis failed or timed out", throwable);
                    return Mono.just(enhanceLayer1Decision(layer1Decision, System.currentTimeMillis()));
                });
    }

    /**
     * 세션 컨텍스트 구축
     * PRIMARY: SecurityEvent → SECONDARY: Redis (보강)
     */
    private SessionContext buildSessionContext(SecurityEvent event) {
        String sessionId = event.getSessionId();

        // 캐시 확인
        if (sessionId != null) {
            SessionContext cached = sessionContextCache.get(sessionId);
            if (cached != null && cached.isValid()) {
                cached.addEvent(event);
                return cached;
            }
        }

        // PRIMARY SOURCE: SecurityEvent
        SessionContext context = new SessionContext();
        context.setSessionId(sessionId);
        context.setUserId(event.getUserId());  // ⭐ event에서 직접
        context.setIpAddress(event.getSourceIp());  // ⭐ event에서 직접
        context.setStartTime(event.getTimestamp() != null ? event.getTimestamp() : LocalDateTime.now());  // ⭐ event에서 직접

        // authMethod 추출 (metadata)
        if (event.getMetadata() != null) {
            Object authMethodObj = event.getMetadata().get("authMethod");
            if (authMethodObj != null) {
                context.setAuthMethod(authMethodObj.toString());
            }
        }

        // SECONDARY SOURCE: Redis (보강만, 실패해도 무시)
        if (sessionId != null && redisTemplate != null) {
            try {
                List<String> recentActions = (List<String>) (List<?>) redisTemplate.opsForList()
                        .range("session:actions:" + sessionId, -10, -1);
                if (recentActions != null && !recentActions.isEmpty()) {
                    context.setRecentActions(recentActions);
                }
            } catch (Exception e) {
                log.debug("Redis enrichment failed: {}", e.getMessage());
            }
        }

        context.addEvent(event);

        // 캐시 저장 (유효한 userId가 있는 경우만)
        if (sessionId != null && context.getUserId() != null) {
            sessionContextCache.put(sessionId, context);
        }

        return context;
    }

    /**
     * 행동 패턴 분석 - AI Native: Baseline 컨텍스트 포함 (v3.0)
     */
    private BehaviorAnalysis analyzeBehaviorPatterns(SecurityEvent event, SessionContext sessionContext) {
        BehaviorAnalysis analysis = new BehaviorAnalysis();
        String userId = event.getUserId();

        // 정상 행동 점수 계산
        double normalScore = calculateNormalBehaviorScore(event, sessionContext);
        analysis.setNormalBehaviorScore(normalScore);

        // 이상 징후 탐지 (빈 리스트 방지)
        List<String> anomalies = detectAnomalies(event, sessionContext);
        if (anomalies.isEmpty()) {
            anomalies.add("[NO_BASELINE: insufficient historical data for anomaly detection]");
        }
        analysis.setAnomalyIndicators(anomalies);

        // 시간적 패턴 분석 (항상 정보 제공)
        String temporalPattern = analyzeTemporalPattern(event);
        analysis.setTemporalPattern(temporalPattern);

        // 유사 이벤트 조회 (빈 리스트 방지)
        List<String> similarEvents = findSimilarEvents(event);
        if (similarEvents.isEmpty()) {
            similarEvents.add("[FIRST_EVENT: no previous similar events found]");
        }
        analysis.setSimilarEvents(similarEvents);

        // AI Native: Baseline 컨텍스트 및 편차 분석 (v3.0)
        if (baselineLearningService != null && userId != null) {
            analysis.setBaselineContext(baselineLearningService.buildBaselinePromptContext(userId, event));
            analysis.setDeviationAnalysis(baselineLearningService.analyzeDeviations(userId, event));
            analysis.setDeviationScore(baselineLearningService.calculateDeviationScore(userId, event));
            analysis.setBaselineEstablished(baselineLearningService.getBaseline(userId) != null);
            log.debug("[Layer2] Baseline context generated for user {}: deviationScore={}",
                userId, analysis.getDeviationScore());
        } else {
            analysis.setBaselineContext(null);
            analysis.setDeviationAnalysis(null);
            analysis.setDeviationScore(Double.NaN);
            analysis.setBaselineEstablished(false);
        }

        return analysis;
    }

    /**
     * 정상 행동 점수 계산 - Vector-based
     */
    private double calculateNormalBehaviorScore(SecurityEvent event, SessionContext context) {
        if (localHcadVectorService == null) {
            return calculateNormalBehaviorScoreFallback(event, context);
        }

        try {
            HCADContext hcadContext = convertToHCADContext(event, context);
            float[] contextEmbedding = localHcadVectorService.generateContextEmbedding(hcadContext);
            double anomalyScore = localHcadVectorService.calculateRealTimeAnomalyScore(
                    contextEmbedding,
                    event.getUserId() != null ? event.getUserId() : "unknown"
            );
            return Math.max(0.1, 1.0 - anomalyScore);
        } catch (Exception e) {
            log.warn("Vector-based score calculation failed, using fallback", e);
            return calculateNormalBehaviorScoreFallback(event, context);
        }
    }

    /**
     * AI Native: 규칙 기반 Fallback 완전 제거
     * - 세션 시간, 접근 빈도, IP 일치, 시간대 규칙 모두 제거
     * - Vector 서비스 실패 시 LLM 분석 필요 상태를 NaN으로 표시
     * - LLM이 컨텍스트를 분석하여 점수를 직접 판단해야 함
     */
    private double calculateNormalBehaviorScoreFallback(SecurityEvent event, SessionContext context) {
        log.warn("[Layer2][AI Native] Vector service unavailable, returning NaN for LLM to analyze");
        return Double.NaN;
    }

    /**
     * 이상 징후 탐지 - Vector + Z-Score 기반
     */
    private List<String> detectAnomalies(SecurityEvent event, SessionContext context) {
        List<String> anomalies = new ArrayList<>();

        if (localHcadVectorService == null) {
            return detectAnomaliesFallback(event, context);
        }

        try {
            HCADContext hcadContext = convertToHCADContext(event, context);
            float[] contextEmbedding = localHcadVectorService.generateContextEmbedding(hcadContext);
            String userId = event.getUserId() != null ? event.getUserId() : "unknown";
            double anomalyScore = localHcadVectorService.calculateRealTimeAnomalyScore(contextEmbedding, userId);

            if (anomalyScore > 0.7) {
                anomalies.add(String.format("High vector-based anomaly score: %.2f", anomalyScore));
            }

            BaselineVector baseline = getOrCreateBaseline(userId);
            if (baseline != null && baseline.getUpdateCount() > 10) {
                double zScore = baseline.calculateZScore(anomalyScore);
                if (zScore > 2.5) {
                    anomalies.add(String.format("Statistical outlier detected (Z-score: %.2f)", zScore));
                }
            }

            String currentScenario = hcadVectorService.detectScenario(hcadContext);
            String expectedScenario = baseline != null ? baseline.getActiveScenario() : null;
            if (expectedScenario != null && !expectedScenario.equals(currentScenario)) {
                anomalies.add(String.format("Unexpected scenario: expected %s, got %s", expectedScenario, currentScenario));
            }

            if (baseline != null && !isIpInNormalRange(event.getSourceIp(), baseline)) {
                anomalies.add("IP address change detected: " + event.getSourceIp());
            }

        } catch (Exception e) {
            log.warn("Vector-based anomaly detection failed, using fallback", e);
            return detectAnomaliesFallback(event, context);
        }

        return anomalies;
    }

    /**
     * AI Native: 규칙 기반 Fallback 완전 제거
     * - 접근 빈도, IP 변경, 시간대, 권한 상승 규칙 모두 제거
     * - Vector 서비스 실패 시 빈 리스트 반환 (LLM이 직접 판단)
     * - LLM이 이상 징후를 컨텍스트 분석으로 직접 탐지해야 함
     */
    private List<String> detectAnomaliesFallback(SecurityEvent event, SessionContext context) {
        log.warn("[Layer2][AI Native] Vector service unavailable, anomaly detection delegated to LLM");
        return new ArrayList<>();
    }

    /**
     * 시간적 패턴 분석 - Scenario Detection
     */
    private String analyzeTemporalPattern(SecurityEvent event) {
        if (hcadVectorService == null) {
            return analyzeTemporalPatternFallback(event);
        }

        try {
            HCADContext hcadContext = convertToHCADContext(event, buildSessionContext(event));
            String scenario = hcadVectorService.detectScenario(hcadContext);

            Map<String, String> scenarioDescriptions = Map.of(
                    "weekday_office", "업무 시간대 사내 네트워크 접속",
                    "weekday_remote", "업무 시간대 외부 네트워크 접속",
                    "weekday_mobile", "업무 시간대 모바일 접속",
                    "evening_activity", "저녁 시간대 활동",
                    "night_activity", "야간 시간대 활동 (주의 필요)",
                    "weekend_home", "주말 가정 네트워크 접속",
                    "weekend_external", "주말 외부 네트워크 접속",
                    "early_morning", "이른 아침 시간대 활동"
            );

            return scenarioDescriptions.getOrDefault(scenario, scenario);

        } catch (Exception e) {
            log.warn("Scenario detection failed, using fallback", e);
            return analyzeTemporalPatternFallback(event);
        }
    }

    /**
     * AI Native: 규칙 기반 Fallback 완전 제거
     * - 9-18시, 22-6시 등 시간대 분류 규칙 제거
     * - Scenario Detection 실패 시 LLM 분석 필요 상태 표시
     * - LLM이 시간 컨텍스트를 직접 분석하여 패턴 판단
     */
    private String analyzeTemporalPatternFallback(SecurityEvent event) {
        log.warn("[Layer2][AI Native] Scenario detection unavailable, temporal pattern analysis delegated to LLM");
        return "[LLM_ANALYSIS_REQUIRED: temporal pattern detection unavailable]";
    }

    /**
     * 유사 이벤트 검색 - Vector Similarity Search
     */
    private List<String> findSimilarEvents(SecurityEvent event) {
        if (behaviorVectorService == null) {
            return findSimilarEventsFallback(event);
        }

        try {
            String userId = event.getUserId() != null ? event.getUserId() : "unknown";
            List<Document> similarBehaviors = behaviorVectorService.findSimilarBehaviors(
                    userId,
                    event.getEventType() != null ? event.getEventType().toString() : "unknown",
                    5
            );

            return similarBehaviors.stream()
                    .map(doc -> {
                        Map<String, Object> meta = doc.getMetadata();
                        return String.format("EventID:%s, Time:%s, Score:%.2f",
                                meta.get("eventId"),
                                meta.get("timestamp"),
                                meta.getOrDefault("similarityScore", 0.0));
                    })
                    .collect(Collectors.toList());

        } catch (Exception e) {
            log.warn("Similar events search failed, using fallback", e);
            return findSimilarEventsFallback(event);
        }
    }

    private List<String> findSimilarEventsFallback(SecurityEvent event) {
        List<String> similar = new ArrayList<>();
        if (redisTemplate != null) {
            try {
                Set<String> keys = redisTemplate.keys("event:similar:" + event.getEventType() + ":*");
                if (keys != null) {
                    similar = keys.stream()
                            .limit(5)
                            .map(key -> key.substring(key.lastIndexOf(":") + 1))
                            .collect(Collectors.toList());
                }
            } catch (Exception e) {
                log.debug("Failed to find similar events", e);
            }
        }
        return similar;
    }

    /**
     * 벡터 스토어에서 관련 문서 검색 (확장된 RAG 검색)
     */
    private List<Document> searchRelatedContext(SecurityEvent event) {
        if (unifiedVectorService == null) {
            return Collections.emptyList();
        }

        try {
            String targetResource = eventEnricher.getTargetResource(event).orElse("unknown");
            String httpMethod = eventEnricher.getHttpMethod(event).orElse("unknown");

            // 확장된 검색 쿼리 - 행동 패턴 분석 관련 정보 포함
            StringBuilder queryBuilder = new StringBuilder();
            queryBuilder.append(event.getEventType()).append(" ");
            queryBuilder.append(targetResource).append(" ");
            queryBuilder.append(httpMethod).append(" ");

            // 사용자 행동 패턴 검색을 위한 컨텍스트 추가
            if (event.getUserId() != null && !event.getUserId().equals("unknown")) {
                queryBuilder.append("user:").append(event.getUserId()).append(" ");
            }

            // 세션 기반 행동 패턴 검색
            if (event.getSessionId() != null) {
                queryBuilder.append("session ");
            }

            // 위협 타입 기반 검색
            if (event.getThreatType() != null && !event.getThreatType().isBlank()) {
                queryBuilder.append(event.getThreatType()).append(" ");
            }

            String query = queryBuilder.toString().trim();

            // AI Native: 임계값 최소화 - LLM이 문서 관련성을 직접 판단
            // 플랫폼은 가능한 모든 컨텍스트를 제공하고, LLM이 가치를 평가함
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(Math.min(15, vectorSearchLimit * 2))
                    .similarityThreshold(0.0)
                    .build();

            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);

            log.debug("RAG behavioral context search: {} documents found for event {}",
                documents != null ? documents.size() : 0, event.getEventId());

            return documents != null ? documents : Collections.emptyList();

        } catch (Exception e) {
            log.debug("Vector store context search failed", e);
            return Collections.emptyList();
        }
    }

    /**
     * SessionContext 변환
     */
    private Layer2PromptTemplate.SessionContext convertToTemplateSessionContext(SessionContext sessionContext) {
        Layer2PromptTemplate.SessionContext ctx = new Layer2PromptTemplate.SessionContext();
        ctx.setSessionId(sessionContext.getSessionId());
        ctx.setUserId(sessionContext.getUserId());
        ctx.setAuthMethod(sessionContext.getAuthMethod());
        ctx.setRecentActions(sessionContext.getRecentActions());
        ctx.setSessionDuration(sessionContext.getSessionDuration());
        ctx.setAccessPattern(sessionContext.getAccessPattern());
        return ctx;
    }

    /**
     * BehaviorAnalysis 변환 - AI Native: Baseline 필드 포함 (v3.0)
     */
    private Layer2PromptTemplate.BehaviorAnalysis convertToTemplateBehaviorAnalysis(BehaviorAnalysis behaviorAnalysis) {
        Layer2PromptTemplate.BehaviorAnalysis ctx = new Layer2PromptTemplate.BehaviorAnalysis();
        ctx.setNormalBehaviorScore(behaviorAnalysis.getNormalBehaviorScore());
        ctx.setAnomalyIndicators(behaviorAnalysis.getAnomalyIndicators());
        ctx.setTemporalPattern(behaviorAnalysis.getTemporalPattern());
        ctx.setSimilarEvents(behaviorAnalysis.getSimilarEvents());

        // AI Native: Baseline 필드 변환 (v3.0)
        ctx.setBaselineContext(behaviorAnalysis.getBaselineContext());
        ctx.setDeviationAnalysis(behaviorAnalysis.getDeviationAnalysis());
        ctx.setDeviationScore(behaviorAnalysis.getDeviationScore());
        ctx.setBaselineEstablished(behaviorAnalysis.isBaselineEstablished());

        return ctx;
    }

    /**
     * Layer2SecurityResponse를 SecurityDecision으로 변환
     */
    private SecurityDecision convertToSecurityDecision(Layer2SecurityResponse response,
                                                       SecurityEvent event,
                                                       SecurityDecision layer1Decision) {
        SecurityDecision.Action action = mapStringToAction(response.getAction());

        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(response.getRiskScore() != null ? response.getRiskScore() : layer1Decision.getRiskScore())
                .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                .threatCategory(response.getThreatCategory())
                .mitigationActions(response.getMitigationActions())
                .reasoning(response.getReasoning())
                .eventId(event.getEventId())
                .analysisTime(System.currentTimeMillis())
                .build();

        if (response.getBehaviorPatterns() != null) {
            decision.setBehaviorPatterns(response.getBehaviorPatterns());
        }
        if (response.getSessionAnalysis() != null) {
            decision.setSessionContext(response.getSessionAnalysis());
        }

        return decision;
    }

    /**
     * JSON 응답 파싱 (수동 파싱으로 BeanOutputConverter 제거)
     *
     * @param jsonResponse LLM이 생성한 JSON 문자열
     * @return Layer2SecurityResponse 객체
     */
    private Layer2SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            // JSON 문자열에서 {}만 추출
            String cleanedJson = extractJsonObject(jsonResponse);
            JsonNode jsonNode = objectMapper.readTree(cleanedJson);

            // AI Native: LLM 응답에서 필수 필드 추출 (기본값 규칙 제거)
            // 필드가 없으면 null 반환 → validateAndFixResponse()에서 NaN 처리
            Double riskScore = jsonNode.has("riskScore") && !jsonNode.get("riskScore").isNull()
                    ? jsonNode.get("riskScore").asDouble() : null;
            Double confidence = jsonNode.has("confidence") && !jsonNode.get("confidence").isNull()
                    ? jsonNode.get("confidence").asDouble() : null;
            String action = jsonNode.has("action") ? jsonNode.get("action").asText() : "ALLOW";
            String reasoning = jsonNode.has("reasoning") ? jsonNode.get("reasoning").asText() : "No reasoning provided";
            String threatCategory = jsonNode.has("threatCategory") ? jsonNode.get("threatCategory").asText() : "UNKNOWN";

            // mitigationActions 배열 파싱
            List<String> mitigationActions = new ArrayList<>();
            if (jsonNode.has("mitigationActions") && jsonNode.get("mitigationActions").isArray()) {
                jsonNode.get("mitigationActions").forEach(node -> mitigationActions.add(node.asText()));
            }

            // Response 객체 생성
            Layer2SecurityResponse response = Layer2SecurityResponse.builder()
                    .riskScore(riskScore)
                    .confidence(confidence)
                    .action(action)
                    .reasoning(reasoning)
                    .threatCategory(threatCategory)
                    .mitigationActions(mitigationActions)
                    .behaviorPatterns(new ArrayList<>())
                    .sessionAnalysis(new HashMap<>())
                    .relatedEvents(new ArrayList<>())
                    .build();

            // 검증 및 수정
            return validateAndFixResponse(response);

        } catch (Exception e) {
            log.error("Failed to parse JSON response from Layer2 LLM: {}", jsonResponse, e);
            return createDefaultResponse();
        }
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
     * 기본 Layer2SecurityResponse 생성
     *
     * AI Native: 규칙 기반 기본값 제거
     * - riskScore/confidence는 NaN 사용 (0.5 규칙 제거)
     * - LLM 분석 불가 상태를 명시적으로 표시
     * - 플랫폼은 분석 불가 상태를 후속 처리에 전달
     */
    private Layer2SecurityResponse createDefaultResponse() {
        return Layer2SecurityResponse.builder()
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .action("ESCALATE")  // AI Native: 분석 불가 시 상위 Layer로 에스컬레이션
                .reasoning("[AI Native] Layer 2 LLM analysis unavailable - escalating to Layer 3")
                .threatCategory("UNKNOWN")
                .behaviorPatterns(new ArrayList<>())
                .mitigationActions(new ArrayList<>())
                .sessionAnalysis(new HashMap<>())
                .relatedEvents(new ArrayList<>())
                .recommendation("ESCALATE")
                .build();
    }

    /**
     * 문자열을 액션으로 매핑
     */
    private SecurityDecision.Action mapStringToAction(String action) {
        if (action == null) return SecurityDecision.Action.MONITOR;
        return switch (action.toUpperCase()) {
            case "ALLOW" -> SecurityDecision.Action.ALLOW;
            case "BLOCK" -> SecurityDecision.Action.BLOCK;
            case "MITIGATE" -> SecurityDecision.Action.MITIGATE;
            case "INVESTIGATE" -> SecurityDecision.Action.INVESTIGATE;
            case "ESCALATE" -> SecurityDecision.Action.ESCALATE;
            default -> SecurityDecision.Action.MONITOR;
        };
    }

    /**
     * 결정에 컨텍스트 정보 추가
     */
    private void enrichDecisionWithContext(SecurityDecision decision,
                                           SessionContext sessionContext,
                                           BehaviorAnalysis behaviorAnalysis) {

        // 세션 컨텍스트를 메타데이터로 추가
        Map<String, Object> sessionData = new HashMap<>();
        sessionData.put("sessionId", sessionContext.getSessionId());
        sessionData.put("userId", sessionContext.getUserId());
        sessionData.put("sessionDuration", sessionContext.getSessionDuration());
        sessionData.put("accessFrequency", sessionContext.getAccessFrequency());

        decision.setSessionContext(sessionData);

        // 행동 패턴 정보 추가
        if (decision.getBehaviorPatterns() == null) {
            decision.setBehaviorPatterns(new ArrayList<>());
        }
        decision.getBehaviorPatterns().addAll(behaviorAnalysis.getAnomalyIndicators());
    }

    /**
     * Layer 1 결정 향상
     */
    private SecurityDecision enhanceLayer1Decision(SecurityDecision layer1Decision, long startTime) {
        // Layer 1 결정을 기반으로 Layer 2 메타데이터 추가
        SecurityDecision enhanced = SecurityDecision.builder()
                .action(layer1Decision.getAction())
                .riskScore(layer1Decision.getRiskScore())
                .confidence(layer1Decision.getConfidence() * 0.9) // 신뢰도 약간 감소
                .analysisTime(startTime)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .processingLayer(2)
                .eventId(layer1Decision.getEventId())
                .reasoning("Layer 2 analysis failed, using enhanced Layer 1 decision")
                .build();

        // Layer 1 필드 복사
        enhanced.setMatchedPattern(layer1Decision.getMatchedPattern());
        enhanced.setKnownThreat(layer1Decision.isKnownThreat());
        enhanced.setLlmModel(modelName);

        return enhanced;
    }

    /**
     * 세션 컨텍스트 업데이트
     */
    private void updateSessionContext(SecurityEvent event, SecurityDecision decision) {
        String sessionId = event.getSessionId();
        if (sessionId == null || redisTemplate == null) return;

        try {
            // 세션 활동 기록
            redisTemplate.opsForList().rightPush(
                    "session:actions:" + sessionId,
                    String.format("%s:%s:%s", event.getEventType(),
                            eventEnricher.getTargetResource(event).orElse("unknown"),
                            decision.getAction())
            );

            // 위험 점수 업데이트
            if (decision.getRiskScore() > 0.7) {
                redisTemplate.opsForValue().set(
                        "session:risk:" + sessionId,
                        decision.getRiskScore(),
                        Duration.ofHours(1)
                );
            }

        } catch (Exception e) {
            log.debug("Failed to update session context", e);
        }
    }

    /**
     * 벡터 데이터베이스에 저장 (UnifiedVectorService 사용)
     * 주의: 쓰기 작업이므로 UnifiedVectorService의 통합 저장소 사용
     */
    private void storeInVectorDatabase(SecurityEvent event, SecurityDecision decision) {
        if (unifiedVectorService == null) return;

        // AI Native: confidence가 유효하지 않으면 저장하지 않음
        // LLM이 확신하지 않는 분석 결과는 학습 데이터 품질을 저하시킬 수 있음
        Double confidence = decision.getConfidence();
        if (confidence == null || Double.isNaN(confidence)) {
            log.debug("Skipping vector storage: confidence not available for event {}", event.getEventId());
            return;
        }

        try {
            // 학습용 문서 생성
            String content = String.format(
                    "Event: %s, Risk: %.2f, Action: %s, Pattern: %s, Reasoning: %s",
                    event.getEventType(),
                    decision.getRiskScore(),
                    decision.getAction(),
                    decision.getThreatCategory(),
                    decision.getReasoning()
            );

            Map<String, Object> metadata = new HashMap<>();

            // 필수 공통 metadata
            metadata.put("documentType", VectorDocumentType.BEHAVIOR.getValue());
            metadata.put("eventId", event.getEventId());
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            metadata.put("userId", event.getUserId() != null ? event.getUserId() : "unknown");

            // SecurityEvent 정보
            metadata.put("eventType", event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN");
            metadata.put("sourceIp", event.getSourceIp());
            metadata.put("sessionId", event.getSessionId());

            // SecurityDecision 정보
            metadata.put("riskScore", decision.getRiskScore());
            metadata.put("action", decision.getAction().toString());
            metadata.put("confidence", decision.getConfidence());
            metadata.put("threatCategory", decision.getThreatCategory() != null ? decision.getThreatCategory() : "UNKNOWN");

            // Layer3 ThreatIntelligence용 (실제 운영에서는 위협 분석 결과 기반)
            if (decision.getRiskScore() >= 0.7) {
                // 고위험: 위협으로 간주
                metadata.put("threatActor", "SUSPICIOUS-" + (event.getSourceIp() != null ? event.getSourceIp().replace(".", "-") : "UNKNOWN"));
                metadata.put("campaignId", "AUTO-" + UUID.randomUUID().toString().substring(0, 8));
                metadata.put("campaignName", "Automated Threat Detection");
                metadata.put("incidentId", "INC-" + UUID.randomUUID().toString().substring(0, 8));
                metadata.put("mitreTactic", "TA0043-Reconnaissance");  // 기본 전술
                metadata.put("assetCriticality", "HIGH");
            } else {
                // 저위험: 정상으로 간주
                metadata.put("threatActor", "NONE");
                metadata.put("campaignId", "NONE");
                metadata.put("campaignName", "");
                metadata.put("incidentId", "");
                metadata.put("mitreTactic", "");
                metadata.put("assetCriticality", "LOW");
            }

            // IOC 지표 (anomalyIndicators가 있으면)
            if (decision.getReasoning() != null && decision.getReasoning().contains("anomaly")) {
                metadata.put("iocIndicator", "anomaly_detected");
            } else {
                metadata.put("iocIndicator", "");
            }

            Document document = new Document(content, metadata);
            unifiedVectorService.storeDocument(document);

            // Phase 1: 고위험 이벤트는 별도로 threat 문서 저장
            if (decision.getRiskScore() >= 0.7 || decision.getThreatCategory() != null && !decision.getThreatCategory().equals("UNKNOWN")) {
                storeThreatDocument(event, decision, content);
            }

        } catch (Exception e) {
            log.debug("Failed to store in vector database (via cache layer)", e);
        }
    }

    /**
     * Phase 1: 위협 패턴 전용 문서 저장 (Layer2 컨텍스트 분석)
     *
     * riskScore >= 0.7 또는 threatCategory가 명확한 경우 threat 문서로 별도 저장
     */
    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, String analysisContent) {
        try {
            Map<String, Object> threatMetadata = new HashMap<>();

            // 위협 전용 documentType (Enum 사용)
            threatMetadata.put("documentType", VectorDocumentType.THREAT.getValue());
            threatMetadata.put("threatConfirmed", decision.getRiskScore() >= 0.8);
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

            // Layer2 특화 정보: 행동 패턴
            if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
                threatMetadata.put("behaviorPatterns", String.join(", ", decision.getBehaviorPatterns()));
            }

            // MITRE ATT&CK
            threatMetadata.put("mitreTactic", determineMitreTactic(decision));
            threatMetadata.put("patternType", decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty() ? "behavioral_anomaly" : "contextual_risk");

            // Layer 정보
            threatMetadata.put("processingLayer", "Layer2");
            threatMetadata.put("confidence", decision.getConfidence());
            threatMetadata.put("action", decision.getAction().toString());

            // IOC 지표 (행동 패턴 기반)
            if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
                threatMetadata.put("iocIndicators", "behavior:" + String.join("|", decision.getBehaviorPatterns()));
            }

            // 위협 설명 (AI 분석 결과 포함)
            String threatDescription = String.format(
                "Layer2 Contextual Threat: User=%s, EventType=%s, IP=%s, RiskScore=%.2f, " +
                "ThreatCategory=%s, BehaviorPatterns=%s, Action=%s, Reasoning=%s",
                event.getUserId(), event.getEventType(), event.getSourceIp(),
                decision.getRiskScore(), decision.getThreatCategory(),
                decision.getBehaviorPatterns() != null ? decision.getBehaviorPatterns() : "[]",
                decision.getAction(),
                decision.getReasoning() != null ? decision.getReasoning().substring(0, Math.min(100, decision.getReasoning().length())) : ""
            );

            Document threatDoc = new Document(threatDescription, threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

            log.info("[Layer2] 위협 패턴 저장 완료: userId={}, riskScore={}, threatType={}, behaviorPatterns={}",
                event.getUserId(), decision.getRiskScore(), threatMetadata.get("threatType"),
                decision.getBehaviorPatterns() != null ? decision.getBehaviorPatterns().size() : 0);

        } catch (Exception e) {
            log.warn("[Layer2] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }

    /**
     * SecurityDecision 기반 위협 유형 분류
     *
     * AI Native 전환:
     * - 패턴 매칭 규칙 완전 제거
     * - LLM이 threatCategory를 직접 결정
     */
    private String determineThreatType(SecurityDecision decision) {
        // AI Native: 패턴 매칭 규칙 완전 제거
        // LLM이 threatCategory를 직접 결정하므로 그대로 반환
        if (decision.getThreatCategory() != null && !decision.getThreatCategory().isBlank()) {
            return decision.getThreatCategory();
        }

        // AI Native: LLM이 threatCategory를 반환하지 않은 경우 null 반환
        return null;
    }

    /**
     * MITRE ATT&CK 전술 매핑
     *
     * AI Native 전환:
     * - 규칙 기반 매핑 완전 제거
     * - LLM이 mitreTactic을 직접 결정하도록 위임
     * - SecurityDecision에 mitreTactic 필드 추가 필요
     */
    private String determineMitreTactic(SecurityDecision decision) {
        // AI Native: 규칙 기반 매핑 완전 제거
        // LLM이 mitreTactic을 직접 결정해야 함
        // 현재는 null 반환 (PromptTemplate에서 mitreTactic 반환하도록 수정 필요)
        return null;
    }



    @Override
    protected String getLayerName() {
        return "Layer2";
    }

    /**
     * 기본 보안 결정 생성
     *
     * AI Native 전환:
     * - 규칙 기반 기본값 제거
     * - LLM 분석 필요 상태를 NaN으로 표시
     */
    private SecurityDecision createDefaultDecision() {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ESCALATE)
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .analysisTime(System.currentTimeMillis())
                .processingLayer(1)
                .build();
    }



    @Override
    public String getStrategyName() {
        return "Layer2-Contextual-Strategy";
    }

    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        // ThreatIndicator 추출 로직
        return new ArrayList<>();
    }

    @Override
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        mapping.put("framework", "CONTEXTUAL_ANALYSIS");
        mapping.put("tier", "2");
        return mapping;
    }

    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        actions.add("MONITOR_USER_BEHAVIOR");
        actions.add("ANALYZE_SESSION_CONTEXT");
        return actions;
    }

    /**
     * AI Native: 규칙 기반 위험 점수 계산 제거
     * - indicators.size() * 0.15 공식 제거
     * - LLM이 riskScore를 직접 반환해야 함
     * - 이 메서드가 호출되면 LLM 분석 결과 없음을 의미
     */
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        log.warn("[Layer2][AI Native] calculateRiskScore called without LLM analysis - returning NaN");
        return Double.NaN;
    }

    // AI Native 전환: mapRiskScoreToThreatLevel() 규칙 기반 매핑 제거
    // LLM이 threatLevel을 직접 결정하므로 이 메서드는 더 이상 사용하지 않음

    private String mapActionToRecommendation(SecurityDecision.Action action) {
        switch (action) {
            case BLOCK:
                return "BLOCK_IMMEDIATELY";
            case ALLOW:
                return "ALLOW";
            case MITIGATE:
                return "APPLY_MITIGATION";
            case INVESTIGATE:
                return "INVESTIGATE_FURTHER";
            case ESCALATE:
                return "ESCALATE_TO_EXPERT";
            default:
                return "MONITOR";
        }
    }

    private HCADContext convertToHCADContext(SecurityEvent event, SessionContext sessionContext) {
        return HCADContext.builder()
                .userId(event.getUserId())
                .sessionId(sessionContext.getSessionId())
                .requestPath(eventEnricher.getTargetResource(event).orElse("/unknown"))
                .httpMethod(eventEnricher.getHttpMethod(event).orElse("GET"))
                .remoteIp(event.getSourceIp())
                .userAgent(event.getUserAgent() != null ? event.getUserAgent() : "unknown")
                .timestamp(event.getTimestamp() != null ?
                        event.getTimestamp().atZone(java.time.ZoneId.systemDefault()).toInstant() :
                        java.time.Instant.now())
                .currentTrustScore(event.getRiskScore() != null ? (1.0 - event.getRiskScore() / 10.0) : 0.5)
                .recentRequestCount(sessionContext.getRecentActions().size())
                .isNewSession(sessionContext.getSessionDuration() < 5L)
                .authenticationMethod(sessionContext.getAuthMethod())
                .resourceType(classifyResourceType(eventEnricher.getTargetResource(event).orElse("/unknown")))
                .build();
    }

    /**
     * AI Native: 패턴 매칭 규칙 완전 제거
     * - contains("/admin"), "/api", "/secure", "/public" 규칙 제거
     * - 경로를 그대로 반환하여 LLM이 리소스 유형 분류
     * - LLM이 경로 컨텍스트를 분석하여 직접 판단
     */
    private String classifyResourceType(String path) {
        // AI Native: 패턴 매칭 제거, raw 경로 그대로 반환
        return path;
    }

    private BaselineVector getOrCreateBaseline(String userId) {
        if (redisTemplate == null) return null;

        try {
            String key = "hcad:baseline:" + userId;
            BaselineVector baseline = (BaselineVector) redisTemplate.opsForValue().get(key);
            if (baseline == null) {
                baseline = BaselineVector.builder()
                        .userId(userId)
                        .confidence(0.1)
                        .updateCount(0L)
                        .build();
            }
            return baseline;
        } catch (Exception e) {
            log.debug("Failed to get baseline vector", e);
            return null;
        }
    }

    private boolean isIpInNormalRange(String ip, BaselineVector baseline) {
        if (baseline == null || ip == null) return true;

        String[] normalRanges = baseline.getNormalIpRanges();
        if (normalRanges == null || normalRanges.length == 0) return true;

        String ipPrefix = ip.substring(0, Math.min(ip.lastIndexOf('.'), ip.length()));
        return Arrays.stream(normalRanges).anyMatch(range -> ipPrefix.startsWith(range));
    }

    /**
     * 세션 컨텍스트 클래스
     */
    private class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private LocalDateTime startTime;
        private String ipAddress;
        private List<String> recentActions = new ArrayList<>();
        private int accessFrequency = 0;

        public boolean isValid() {
            return startTime != null &&
                    startTime.isAfter(LocalDateTime.now().minusHours(24));
        }

        public void addEvent(SecurityEvent event) {
            accessFrequency++;
            if (recentActions.size() > 100) {
                recentActions.remove(0);
            }
            String targetResource = eventEnricher.getTargetResource(event).orElse("unknown");
            recentActions.add(event.getEventType() + ":" + targetResource);
        }

        public long getSessionDuration() {
            if (startTime == null) return 0;
            return Duration.between(startTime, LocalDateTime.now()).toMinutes();
        }

        public String getAccessPattern() {
            if (accessFrequency < 10) return "Low activity";
            if (accessFrequency < 50) return "Normal activity";
            if (accessFrequency < 200) return "High activity";
            return "Excessive activity";
        }

        // Getters and setters
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId != null ? userId : "unknown"; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod != null ? authMethod : "unknown"; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }

        public String getIpAddress() { return ipAddress != null ? ipAddress : "unknown"; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

        public List<String> getRecentActions() { return recentActions; }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        public int getAccessFrequency() { return accessFrequency; }
    }

    /**
     * 행동 분석 결과
     */
    /**
     * AI 응답 검증 및 수정
     *
     * AI Native: LLM 응답을 가공 없이 그대로 사용
     * - confidence/riskScore가 null이면 Double.NaN 사용 (규칙 기반 기본값 금지)
     * - LLM이 응답하지 않은 것은 "분석 불가" 상태로 명시
     */
    private Layer2SecurityResponse validateAndFixResponse(Layer2SecurityResponse response) {
        if (response == null) {
            return createDefaultResponse();
        }

        // AI Native: confidence가 null이면 NaN 사용 (강제 상향 금지)
        if (response.getConfidence() == null) {
            log.warn("[Layer2][AI Native] LLM이 confidence 미반환 (가공 없이 NaN 사용)");
            response.setConfidence(Double.NaN);
        }

        // AI Native: riskScore가 null이면 NaN 사용 (기본값 금지)
        if (response.getRiskScore() == null) {
            log.warn("[Layer2][AI Native] LLM이 riskScore 미반환 (가공 없이 NaN 사용)");
            response.setRiskScore(Double.NaN);
        }

        // threatCategory 검증 (null인 경우만)
        if (response.getThreatCategory() == null || response.getThreatCategory().equals("none")) {
            response.setThreatCategory("UNKNOWN");
        }

        // mitigationActions 검증
        if (response.getMitigationActions() == null) {
            response.setMitigationActions(new ArrayList<>());
        }

        return response;
    }

    private static class BehaviorAnalysis {
        private double normalBehaviorScore;
        private List<String> anomalyIndicators = new ArrayList<>();
        private String temporalPattern;
        private List<String> similarEvents = new ArrayList<>();

        // AI Native: Baseline 상세 정보 필드 (v3.0)
        private String baselineContext;
        private String deviationAnalysis;
        private double deviationScore;
        private boolean baselineEstablished;

        // Getters and setters
        public double getNormalBehaviorScore() { return normalBehaviorScore; }
        public void setNormalBehaviorScore(double score) { this.normalBehaviorScore = score; }

        public List<String> getAnomalyIndicators() { return anomalyIndicators; }
        public void setAnomalyIndicators(List<String> indicators) { this.anomalyIndicators = indicators; }

        public String getTemporalPattern() { return temporalPattern; }
        public void setTemporalPattern(String pattern) { this.temporalPattern = pattern; }

        public List<String> getSimilarEvents() { return similarEvents; }
        public void setSimilarEvents(List<String> events) { this.similarEvents = events; }

        // AI Native: Baseline 필드 Getter/Setter
        public String getBaselineContext() { return baselineContext; }
        public void setBaselineContext(String baselineContext) { this.baselineContext = baselineContext; }

        public String getDeviationAnalysis() { return deviationAnalysis; }
        public void setDeviationAnalysis(String deviationAnalysis) { this.deviationAnalysis = deviationAnalysis; }

        public double getDeviationScore() { return deviationScore; }
        public void setDeviationScore(double deviationScore) { this.deviationScore = deviationScore; }

        public boolean isBaselineEstablished() { return baselineEstablished; }
        public void setBaselineEstablished(boolean baselineEstablished) { this.baselineEstablished = baselineEstablished; }
    }
}