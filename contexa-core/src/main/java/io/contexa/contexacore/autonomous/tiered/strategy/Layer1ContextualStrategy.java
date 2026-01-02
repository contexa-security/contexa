package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.response.Layer1SecurityResponse;
import io.contexa.contexacore.autonomous.tiered.template.Layer1PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
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
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import reactor.core.publisher.Mono;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

@Slf4j

public class Layer1ContextualStrategy extends AbstractTieredStrategy {

    private final UnifiedLLMOrchestrator llmOrchestrator;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityEventEnricher eventEnricher;
    private final Layer1PromptTemplate promptTemplate;
    private final BehaviorVectorService behaviorVectorService;
    private final UnifiedVectorService unifiedVectorService;
    private final BaselineLearningService baselineLearningService;
    private final TieredStrategyProperties tieredStrategyProperties;
    private final Cache<String, SessionContext> sessionContextCache;
    private final ObjectMapper objectMapper = new ObjectMapper();


    @Value("${spring.ai.security.layer1.model:llama3.1:8b}")
    private String modelName;

    // AI Native v4.3.0: @Value 타임아웃 제거 - TieredStrategyProperties.Layer1.Timeout 사용
    // 레거시 호환성을 위해 vectorSearchLimit만 유지
    @Value("${spring.ai.security.tiered.layer1.vector-search-limit:10}")
    private int vectorSearchLimit;

    @Autowired
    public Layer1ContextualStrategy(@Autowired(required = false) UnifiedLLMOrchestrator llmOrchestrator,
                                    @Autowired(required = false) UnifiedVectorService unifiedVectorService,
                                    @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                                    @Autowired(required = false) SecurityEventEnricher eventEnricher,
                                    @Autowired(required = false) Layer1PromptTemplate promptTemplate,
                                    @Autowired(required = false) BehaviorVectorService behaviorVectorService,
                                    @Autowired(required = false) BaselineLearningService baselineLearningService,
                                    @Autowired TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.unifiedVectorService = unifiedVectorService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate : new Layer1PromptTemplate(eventEnricher, tieredStrategyProperties);
        this.behaviorVectorService = behaviorVectorService;
        this.baselineLearningService = baselineLearningService;
        this.tieredStrategyProperties = tieredStrategyProperties;

        // Phase 2-5: 메모리 누수 수정 - Caffeine TTL 캐시로 교체
        TieredStrategyProperties.Layer1.Cache cacheConfig = tieredStrategyProperties.getLayer1().getCache();
        this.sessionContextCache = Caffeine.newBuilder()
                .maximumSize(cacheConfig.getMaxSize())
                .expireAfterAccess(cacheConfig.getTtlMinutes(), TimeUnit.MINUTES)
                .recordStats()
                .build();

        log.info("Layer 1 Contextual Strategy initialized with UnifiedLLMOrchestrator");
        log.info("  - Model: {}", modelName);
        // AI Native v4.3.0: 타임아웃 설정 로깅
        TieredStrategyProperties.Layer1.Timeout timeout = tieredStrategyProperties.getLayer1().getTimeout();
        log.info("  - Timeout: total={}ms, llm={}ms, vector={}ms, redis={}ms, baseline={}ms",
            timeout.getTotalMs(), timeout.getLlmMs(), timeout.getVectorSearchMs(),
            timeout.getRedisMs(), timeout.getBaselineMs());
        log.info("  - UnifiedVectorService available: {}", unifiedVectorService != null);
        log.info("  - BaselineLearningService available: {}", baselineLearningService != null);
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.info("Layer 1 Contextual Strategy evaluating event: {}", event.getEventId());

        // AI Native v4.2.0: Layer1이 첫 번째 레이어이므로 이전 레이어 결과 없음
        SecurityDecision decision = analyzeWithContext(event);
        boolean shouldEscalate = decision.getAction() == SecurityDecision.Action.ESCALATE;
        String action = decision.getAction() != null ? decision.getAction().name() : "ESCALATE";
        // AI Native v4.3.0: eventId, assessedAt 추가 (null 필드 정리)
        return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessedAt(LocalDateTime.now())
                .riskScore(decision.getRiskScore())
                .confidence(decision.getConfidence())
                .indicators(new ArrayList<>())
                .recommendedActions(List.of(mapActionToRecommendation(decision.getAction())))
                .strategyName("Layer1-Contextual")
                .shouldEscalate(shouldEscalate)
                .action(action)  // AI Native: LLM action 직접 저장
                .build();
    }

    public SecurityDecision analyzeWithContext(SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            // 1. 세션 컨텍스트 수집
            SessionContext sessionContext = buildSessionContext(event);

            // 2. 행동 패턴 분석
            BehaviorAnalysis behaviorAnalysis = analyzeBehaviorPatterns(event);

            // 3. 벡터 스토어에서 관련 컨텍스트 검색
            List<Document> relatedDocuments = searchRelatedContext(event);

            // 4. PromptTemplate을 통한 프롬프트 구성
            Layer1PromptTemplate.SessionContext sessionCtx = convertToTemplateSessionContext(sessionContext);
            Layer1PromptTemplate.BehaviorAnalysis behaviorCtx = convertToTemplateBehaviorAnalysis(behaviorAnalysis);

            String promptText = promptTemplate.buildPrompt(event, sessionCtx, behaviorCtx, relatedDocuments);

            // AI Native v4.3.0: 설정에서 타임아웃 가져오기
            long llmTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getLlmMs();

            Layer1SecurityResponse response = null;
            if (llmOrchestrator != null) {
                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(promptText))
                        .tier(1)
                        .preferredModel(modelName)
                        .securityTaskType(ExecutionContext.SecurityTaskType.CONTEXTUAL_ANALYSIS)
                        .timeoutMs((int)llmTimeoutMs)
                        .requestId(event.getEventId())
                        .build();

                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(llmTimeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.warn("[Layer1][AI Native] LLM execution failed, escalating to Layer 2: {}", event.getEventId(), e);
                            return Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"ESCALATE\",\"reasoning\":\"[AI Native] LLM execution failed - escalating to Layer 2\",\"threatCategory\":\"UNKNOWN\"}");
                        })
                        .block();

                response = parseJsonResponse(jsonResponse);
            } else {
                log.warn("UnifiedLLMOrchestrator not available for Layer 1 analysis");
                response = createDefaultResponse();
            }

            // 5. 응답을 SecurityDecision 으로 변환
            SecurityDecision decision = convertToSecurityDecision(response, event);

            // 6. 메타데이터 추가
            enrichDecisionWithContext(decision, sessionContext, behaviorAnalysis);
            decision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            decision.setProcessingLayer(1);

            // 7. 세션 컨텍스트 업데이트
            updateSessionContext(event, decision);

            // 8. 벡터 스토어에 저장 (학습용)
            storeInVectorDatabase(event, decision);

            log.info("Layer 1 analysis completed in {}ms - Risk: {}, Action: {}",
                    decision.getProcessingTimeMs(), decision.getRiskScore(), decision.getAction());

            return decision;

        } catch (Exception e) {
            log.error("Layer 1 analysis failed for event {}", event.getEventId(), e);
            return createFallbackDecision(startTime);
        }
    }

    /**
     * 비동기 컨텍스트 분석
     *
     * AI Native v4.3.0: 전체 분석 타임아웃 적용
     * - 모든 작업(Redis, Vector, Baseline, LLM)을 포함한 총 처리 시간 제한
     * - 개별 작업은 각자의 타임아웃으로 보호됨
     */
    public Mono<SecurityDecision> analyzeWithContextAsync(SecurityEvent event) {
        long totalTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getTotalMs();
        return Mono.fromCallable(() -> analyzeWithContext(event))
                .timeout(Duration.ofMillis(totalTimeoutMs))
                .onErrorResume(throwable -> {
                    log.error("[Layer1][AI Native v4.3.0] Async analysis failed or timed out ({}ms)",
                        totalTimeoutMs, throwable);
                    return Mono.just(createFallbackDecision(System.currentTimeMillis()));
                });
    }

    /**
     * 세션 컨텍스트 구축
     * PRIMARY: SecurityEvent → SECONDARY: Redis (보강)
     */
    private SessionContext buildSessionContext(SecurityEvent event) {
        String sessionId = event.getSessionId();

        // 캐시 확인 (Caffeine: getIfPresent 사용)
        if (sessionId != null) {
            SessionContext cached = sessionContextCache.getIfPresent(sessionId);
            if (cached != null && cached.isValid()) {
                // Zero Trust: 컨텍스트 변화 검증 (세션 하이재킹 탐지)
                if (isSessionContextChanged(cached, event)) {
                    log.warn("[Layer1][Zero Trust] Context change detected: session={}, IP={}->{}",
                        sessionId, cached.getIpAddress(), event.getSourceIp());
                    sessionContextCache.invalidate(sessionId);
                    // 캐시 무효화 후 새 컨텍스트 생성으로 진행
                } else {
                    cached.addEvent(event);
                    return cached;
                }
            }
        }

        // PRIMARY SOURCE: SecurityEvent
        SessionContext context = new SessionContext();
        context.setSessionId(sessionId);
        context.setUserId(event.getUserId());  // ⭐ event에서 직접
        context.setIpAddress(event.getSourceIp());  // ⭐ event에서 직접
        // M1: Zero Trust - 서버 타임스탬프만 사용 (클라이언트 시간 조작 방지)
        context.setStartTime(LocalDateTime.now());

        // authMethod 및 recentRequestCount 추출 (metadata)
        if (event.getMetadata() != null) {
            Object authMethodObj = event.getMetadata().get("authMethod");
            if (authMethodObj != null) {
                context.setAuthMethod(authMethodObj.toString());
            }

            // AI Native v4.3.0: metadata.recentRequestCount를 accessFrequency로 사용
            // HCADFilter에서 Redis 기반으로 정확하게 추적한 값이므로 SessionContext 내부 카운터보다 신뢰도 높음
            Object recentRequestCountObj = event.getMetadata().get("recentRequestCount");
            if (recentRequestCountObj instanceof Number) {
                context.setAccessFrequency(((Number) recentRequestCountObj).intValue());
            }
        }

        // SECONDARY SOURCE: Redis (보강만, 실패해도 무시)
        // H1: Redis 타임아웃 적용 - 무한 대기 방지
        if (sessionId != null && redisTemplate != null) {
            long redisTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getRedisMs();
            try {
                CompletableFuture<List<String>> future = CompletableFuture.supplyAsync(() -> {
                    @SuppressWarnings("unchecked")
                    List<String> actions = (List<String>) (List<?>) redisTemplate.opsForList()
                            .range(ZeroTrustRedisKeys.sessionActions(sessionId), -10, -1);
                    return actions;
                });
                List<String> recentActions = future.get(redisTimeoutMs, TimeUnit.MILLISECONDS);
                if (recentActions != null && !recentActions.isEmpty()) {
                    context.setRecentActions(recentActions);
                }
            } catch (TimeoutException e) {
                log.warn("[Layer1] Redis session actions timeout ({}ms) for session {}",
                    redisTimeoutMs, sessionId);
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
     * 행동 패턴 분석
     *
     * AI Native v4.3.0: Baseline 서비스 타임아웃 적용
     * - Baseline 서비스 무한 대기 방지
     * - 타임아웃 시 서비스 불가 상태로 표시
     */
    private BehaviorAnalysis analyzeBehaviorPatterns(SecurityEvent event) {
        BehaviorAnalysis analysis = new BehaviorAnalysis();
        String userId = event.getUserId();

        // 유사 이벤트 조회 (유지 - raw 데이터)
        // AI Native: 빈 리스트는 그대로 유지, 마커 생성 금지
        List<String> similarEvents = findSimilarEvents(event);
        analysis.setSimilarEvents(similarEvents);

        // Zero Trust: 서비스 상태를 명시적으로 LLM에게 전달
        if (baselineLearningService == null) {
            analysis.setBaselineContext("[SERVICE_UNAVAILABLE] Baseline learning service not configured");
            analysis.setBaselineEstablished(false);
        } else if (userId == null) {
            // H2: 인증 사용자 전용 플랫폼 - userId null은 시스템 오류
            log.error("[Layer1][SYSTEM_ERROR] userId is null - authentication system failure");
            analysis.setBaselineContext("[SYSTEM_ERROR] Authentication failure - userId unavailable. " +
                "This should not happen in authenticated platform. Recommend ESCALATE.");
            analysis.setBaselineEstablished(false);
        } else {
            // AI Native v4.3.0: Baseline 서비스 타임아웃 적용
            long baselineTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getBaselineMs();
            try {
                CompletableFuture<String> future = CompletableFuture.supplyAsync(() ->
                    baselineLearningService.buildBaselinePromptContext(userId, event)
                );
                String baselineContext = future.get(baselineTimeoutMs, TimeUnit.MILLISECONDS);

                if (baselineContext == null || baselineContext.isEmpty()) {
                    analysis.setBaselineContext("[NO_DATA] Baseline service returned empty response");
                } else {
                    analysis.setBaselineContext(baselineContext);
                    log.debug("[Layer1] Baseline context generated for user {}", userId);
                }

                // Baseline 존재 여부 확인 (별도 타임아웃 적용)
                CompletableFuture<Boolean> baselineExistsFuture = CompletableFuture.supplyAsync(() ->
                    baselineLearningService.getBaseline(userId) != null
                );
                analysis.setBaselineEstablished(baselineExistsFuture.get(baselineTimeoutMs, TimeUnit.MILLISECONDS));

            } catch (TimeoutException e) {
                log.warn("[Layer1][AI Native v4.3.0] Baseline service timeout ({}ms) for user {}",
                    baselineTimeoutMs, userId);
                analysis.setBaselineContext("[SERVICE_TIMEOUT] Baseline service did not respond in time");
                analysis.setBaselineEstablished(false);
            } catch (Exception e) {
                log.warn("[Layer1] Baseline service error for user {}: {}", userId, e.getMessage());
                analysis.setBaselineContext("[SERVICE_ERROR] Baseline service error: " + e.getMessage());
                analysis.setBaselineEstablished(false);
            }
        }

        return analysis;
    }

    private List<String> findSimilarEvents(SecurityEvent event) {
        if (behaviorVectorService == null) {
            return findSimilarEventsFallback(event);
        }

        // H3: 인증 사용자 전용 플랫폼 - userId null은 시스템 오류
        String userId = event.getUserId();
        if (userId == null) {
            log.error("[Layer1][SYSTEM_ERROR] userId null in findSimilarEvents");
            return Collections.emptyList();
        }

        // AI Native: description이 없으면 의미 있는 검색 불가
        String description = event.getDescription();
        if (description == null || description.isEmpty()) {
            log.debug("[Layer1][AI Native] No description for similar events search, skipping");
            return Collections.emptyList();
        }

        try {
            List<Document> similarBehaviors = behaviorVectorService.findSimilarBehaviors(
                    userId,
                    description,
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

    /**
     * Redis SCAN을 사용한 유사 이벤트 검색 (Fallback)
     *
     * AI Native v4.3.0: 타임아웃 및 시간 제한 적용
     * - Redis SCAN 무한 루프 방지
     * - 설정된 시간 초과 시 현재까지 수집된 결과 반환
     */
    private List<String> findSimilarEventsFallback(SecurityEvent event) {
        List<String> similar = new ArrayList<>();
        if (redisTemplate == null) {
            return similar;
        }

        // H3: 인증 사용자 전용 플랫폼 - userId null은 시스템 오류
        String userId = event.getUserId();
        if (userId == null) {
            log.error("[Layer1][SYSTEM_ERROR] userId null in findSimilarEventsFallback");
            return similar;
        }
        String pattern = "event:similar:" + userId + ":*";
        int limit = 5;
        long redisTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getRedisMs();
        long startTime = System.currentTimeMillis();

        try {
            // Redis SCAN: 점진적 스캔으로 블로킹 방지
            ScanOptions scanOptions = ScanOptions.scanOptions()
                    .match(pattern)
                    .count(100)  // 배치 크기 (한 번에 스캔할 키 수)
                    .build();

            try (Cursor<String> cursor = redisTemplate.scan(scanOptions)) {
                while (cursor.hasNext() && similar.size() < limit) {
                    // AI Native v4.3.0: 시간 제한 체크
                    if (System.currentTimeMillis() - startTime > redisTimeoutMs) {
                        log.warn("[Layer1][AI Native v4.3.0] Redis SCAN timeout ({}ms), returning {} events",
                            redisTimeoutMs, similar.size());
                        break;
                    }
                    String key = cursor.next();
                    String eventId = key.substring(key.lastIndexOf(":") + 1);
                    similar.add(eventId);
                }
            }
        } catch (Exception e) {
            log.debug("[Layer1] Failed to find similar events via SCAN", e);
        }

        return similar;
    }

    /**
     * 벡터 스토어에서 관련 문서 검색 (확장된 RAG 검색)
     * AI Native: eventType, targetResource 제거 - 행동 패턴 기반 검색
     *
     * AI Native v4.3.0: 타임아웃 적용
     * - 벡터 검색 무한 대기 방지
     * - 타임아웃 시 빈 리스트 반환 (LLM 분석은 계속 진행)
     */
    private List<Document> searchRelatedContext(SecurityEvent event) {
        if (unifiedVectorService == null) {
            return Collections.emptyList();
        }

        long vectorSearchTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getVectorSearchMs();

        try {
            // M3: AI Native - "unknown" 하드코딩 제거
            String httpMethod = eventEnricher.getHttpMethod(event).orElse(null);

            // AI Native v4.2.0: 검색 품질 개선 - description, targetResource 포함
            StringBuilder queryBuilder = new StringBuilder();

            // 1. 이벤트 설명 (가장 중요한 검색 키워드)
            if (event.getDescription() != null && !event.getDescription().isEmpty()) {
                queryBuilder.append(event.getDescription()).append(" ");
            }

            // 2. 요청 경로 (targetResource)
            String targetResource = eventEnricher.getTargetResource(event).orElse(null);
            if (targetResource != null && !targetResource.isEmpty()) {
                queryBuilder.append(targetResource).append(" ");
            }

            // 3. HTTP 메서드 (M3: null/"unknown" 제외)
            if (httpMethod != null && !"unknown".equalsIgnoreCase(httpMethod)) {
                queryBuilder.append(httpMethod).append(" ");
            }

            // 4. 사용자 ID (보조 정보)
            if (event.getUserId() != null && !event.getUserId().equals("unknown")) {
                queryBuilder.append("user:").append(event.getUserId()).append(" ");
            }

            // 5. 소스 IP (보조 정보)
            if (event.getSourceIp() != null) {
                queryBuilder.append("IP:").append(event.getSourceIp()).append(" ");
            }

            String query = queryBuilder.toString().trim();
            // AI Native: 빈 쿼리 시 무의미한 기본값 대신 검색 스킵
            if (query.isEmpty()) {
                log.debug("[Layer1][AI Native] Empty query, skipping vector search for event {}",
                    event.getEventId());
                return Collections.emptyList();
            }

            // 설정에서 유사도 임계값 가져오기
            double similarityThreshold = tieredStrategyProperties.getLayer1().getRag().getSimilarityThreshold();

            // H4: AI Native - BEHAVIOR 타입 문서만 검색 (필터 추가)
            String documentTypeFilter = String.format("documentType == '%s'",
                VectorDocumentType.BEHAVIOR.getValue());

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(Math.min(15, vectorSearchLimit * 2))
                    .similarityThreshold(similarityThreshold)
                    .filterExpression(documentTypeFilter)
                    .build();

            // AI Native v4.3.0: 벡터 검색 타임아웃 적용
            CompletableFuture<List<Document>> future = CompletableFuture.supplyAsync(() ->
                unifiedVectorService.searchSimilar(searchRequest)
            );

            List<Document> documents = future.get(vectorSearchTimeoutMs, TimeUnit.MILLISECONDS);

            log.debug("RAG behavioral context search: {} documents found for event {}",
                documents != null ? documents.size() : 0, event.getEventId());

            return documents != null ? documents : Collections.emptyList();

        } catch (TimeoutException e) {
            log.warn("[Layer1][AI Native v4.3.0] Vector search timeout ({}ms) for event {}",
                vectorSearchTimeoutMs, event.getEventId());
            return Collections.emptyList();
        } catch (Exception e) {
            log.debug("Vector store context search failed", e);
            return Collections.emptyList();
        }
    }

    /**
     * SessionContext 변환
     */
    private Layer1PromptTemplate.SessionContext convertToTemplateSessionContext(SessionContext sessionContext) {
        Layer1PromptTemplate.SessionContext ctx = new Layer1PromptTemplate.SessionContext();
        ctx.setSessionId(sessionContext.getSessionId());
        ctx.setUserId(sessionContext.getUserId());
        ctx.setAuthMethod(sessionContext.getAuthMethod());
        ctx.setRecentActions(sessionContext.getRecentActions());
        ctx.setSessionDuration(sessionContext.getSessionDuration());
        // AI Native v4.2.0: setAccessPattern() 호출 삭제 - 프롬프트 미사용
        return ctx;
    }

    private Layer1PromptTemplate.BehaviorAnalysis convertToTemplateBehaviorAnalysis(BehaviorAnalysis behaviorAnalysis) {
        Layer1PromptTemplate.BehaviorAnalysis ctx = new Layer1PromptTemplate.BehaviorAnalysis();

        ctx.setSimilarEvents(behaviorAnalysis.getSimilarEvents());
        ctx.setBaselineContext(behaviorAnalysis.getBaselineContext());
        ctx.setBaselineEstablished(behaviorAnalysis.isBaselineEstablished());

        return ctx;
    }

    /**
     * Layer1SecurityResponse를 SecurityDecision으로 변환
     */
    private SecurityDecision convertToSecurityDecision(Layer1SecurityResponse response,
                                                       SecurityEvent event) {
        SecurityDecision.Action action = mapStringToAction(response.getAction());

        // AI Native: Layer1 점수 폴백 금지 - LLM이 분석 못하면 NaN
        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
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

    private Layer1SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            // JSON 문자열에서 {}만 추출
            String cleanedJson = extractJsonObject(jsonResponse);

            // 1단계: 축약 JSON 파싱 우선 시도 (프롬프트 최적화 후 표준 형식)
            Layer1SecurityResponse compactResponse = Layer1SecurityResponse.fromCompactJson(cleanedJson);
            if (isValidResponse(compactResponse)) {
                log.debug("Layer1 compact JSON parsing successful: {}", cleanedJson);
                // 컬렉션 필드 초기화 (축약 형식에서는 생략됨)
                if (compactResponse.getMitigationActions() == null) {
                    compactResponse.setMitigationActions(new ArrayList<>());
                }
                if (compactResponse.getBehaviorPatterns() == null) {
                    compactResponse.setBehaviorPatterns(new ArrayList<>());
                }
                if (compactResponse.getSessionAnalysis() == null) {
                    compactResponse.setSessionAnalysis(new HashMap<>());
                }
                if (compactResponse.getRelatedEvents() == null) {
                    compactResponse.setRelatedEvents(new ArrayList<>());
                }
                return validateAndFixResponse(compactResponse);
            }

            log.debug("Layer1 compact parsing failed, falling back to Jackson: {}", cleanedJson);
            JsonNode jsonNode = objectMapper.readTree(cleanedJson);
            Double riskScore = jsonNode.has("riskScore") && !jsonNode.get("riskScore").isNull()
                    ? jsonNode.get("riskScore").asDouble() : null;
            Double confidence = jsonNode.has("confidence") && !jsonNode.get("confidence").isNull()
                    ? jsonNode.get("confidence").asDouble() : null;
            // AI Native v4.2.0: null 값이 "null" 문자열로 변환되는 것 방지
            String action = (jsonNode.has("action") && !jsonNode.get("action").isNull())
                    ? jsonNode.get("action").asText() : "ESCALATE";
            String reasoning = (jsonNode.has("reasoning") && !jsonNode.get("reasoning").isNull())
                    ? jsonNode.get("reasoning").asText() : "No reasoning provided";
            // AI Native: threatCategory는 LLM이 분류, 없으면 null 유지
            // 플랫폼이 기본값이나 마커를 생성하지 않음
            String threatCategory = (jsonNode.has("threatCategory") && !jsonNode.get("threatCategory").isNull()
                    && !jsonNode.get("threatCategory").asText().isBlank())
                    ? jsonNode.get("threatCategory").asText() : null;

            List<String> mitigationActions = new ArrayList<>();
            if (jsonNode.has("mitigationActions") && jsonNode.get("mitigationActions").isArray()) {
                jsonNode.get("mitigationActions").forEach(node -> mitigationActions.add(node.asText()));
            }

            // Response 객체 생성
            Layer1SecurityResponse response = Layer1SecurityResponse.builder()
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
     * Response 객체 유효성 검사
     * riskScore 또는 confidence가 설정되어 있으면 유효한 응답으로 판단
     */
    private boolean isValidResponse(Layer1SecurityResponse response) {
        if (response == null) return false;
        return response.getRiskScore() != null || response.getConfidence() != null;
    }

    private Layer1SecurityResponse createDefaultResponse() {
        return Layer1SecurityResponse.builder()
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .action("ESCALATE")  // AI Native: 분석 불가 시 상위 Layer로 에스컬레이션
                .reasoning("Layer 1 LLM analysis unavailable - escalating to Layer 1")
                .threatCategory(null)  // AI Native: 플랫폼이 분류하지 않음
                .behaviorPatterns(new ArrayList<>())
                .mitigationActions(new ArrayList<>())
                .sessionAnalysis(new HashMap<>())
                .relatedEvents(new ArrayList<>())
                .recommendation("ESCALATE")
                .build();
    }

    // mapStringToAction()은 AbstractTieredStrategy로 이동됨

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
        if (decision.getBehaviorPatterns() == null) {
            decision.setBehaviorPatterns(new ArrayList<>());
        }
        decision.getBehaviorPatterns().addAll(behaviorAnalysis.getSimilarEvents());
    }

    /**
     * Layer 1 분석 실패 시 기본 결정 생성
     * AI Native: 분석 실패 시 ESCALATE로 상위 Layer에 위임
     */
    private SecurityDecision createFallbackDecision(long startTime) {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ESCALATE)
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .analysisTime(startTime)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .processingLayer(1)
                .reasoning("[AI Native] Layer 1 analysis failed - escalating to Layer 2")
                .build();
    }

    /**
     * 세션 컨텍스트 업데이트
     * AI Native: eventType, targetResource 제거
     */
    private void updateSessionContext(SecurityEvent event, SecurityDecision decision) {
        String sessionId = event.getSessionId();
        if (sessionId == null || redisTemplate == null) return;

        try {
            // AI Native: 행동 기반 세션 기록 (eventType 제거)
            redisTemplate.opsForList().rightPush(
                    ZeroTrustRedisKeys.sessionActions(sessionId),
                    String.format("%s:%s:%s",
                            event.getDescription() != null ? event.getDescription() : "action",
                            eventEnricher.getHttpMethod(event).orElse("unknown"),
                            decision.getAction())
            );

            // v3.1.0: MITIGATE -> BLOCK으로 통합됨
            SecurityDecision.Action sessionAction = decision.getAction();
            if (sessionAction == SecurityDecision.Action.BLOCK) {
                redisTemplate.opsForValue().set(
                        ZeroTrustRedisKeys.sessionRisk(sessionId),
                        decision.getRiskScore(),
                        Duration.ofHours(1)
                );
            }

        } catch (Exception e) {
            log.debug("Failed to update session context", e);
        }
    }

    private void storeInVectorDatabase(SecurityEvent event, SecurityDecision decision) {
        if (unifiedVectorService == null) return;

        double confidence = decision.getConfidence();
        if (Double.isNaN(confidence)) {
            log.debug("Skipping vector storage: confidence not available for event {}", event.getEventId());
            return;
        }

        try {
            // 학습용 문서 생성 (AI Native: eventType 제거)
            String content = String.format(
                    "User: %s, Risk: %.2f, Action: %s, Pattern: %s, Reasoning: %s",
                    event.getUserId() != null ? event.getUserId() : "unknown",
                    decision.getRiskScore(),
                    decision.getAction(),
                    decision.getThreatCategory(),
                    decision.getReasoning()
            );

            Map<String, Object> metadata = new HashMap<>();

            // 필수 공통 metadata
            metadata.put("documentType", VectorDocumentType.BEHAVIOR.getValue());
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            // AI Native: null인 경우 필드 생략 (LLM이 "unknown"을 실제 값으로 오해 방지)
            if (event.getEventId() != null) {
                metadata.put("eventId", event.getEventId());
            }
            if (event.getUserId() != null) {
                metadata.put("userId", event.getUserId());
            }

            // SecurityEvent 정보 (AI Native: eventType 제거)
            if (event.getSourceIp() != null) {
                metadata.put("sourceIp", event.getSourceIp());
            }
            if (event.getSessionId() != null) {
                metadata.put("sessionId", event.getSessionId());
            }

            // SecurityDecision 정보 (LLM이 직접 결정한 값만 저장)
            // AI Native: NaN인 경우 필드 생략 (LLM이 -1.0을 낮은 값으로 오해 방지)
            double metaRiskScore = decision.getRiskScore();
            double metaConfidence = decision.getConfidence();
            if (!Double.isNaN(metaRiskScore)) {
                metadata.put("riskScore", metaRiskScore);
            }
            metadata.put("action", decision.getAction() != null ? decision.getAction().toString() : "ESCALATE");
            if (!Double.isNaN(metaConfidence)) {
                metadata.put("confidence", metaConfidence);
            }
            // AI Native: null인 경우 필드 생략
            if (decision.getThreatCategory() != null) {
                metadata.put("threatCategory", decision.getThreatCategory());
            }

            Document document = new Document(content, metadata);
            unifiedVectorService.storeDocument(document);

            // v3.1.0: MITIGATE -> BLOCK으로 통합됨
            SecurityDecision.Action vectorAction = decision.getAction();
            if (vectorAction == SecurityDecision.Action.BLOCK) {
                storeThreatDocument(event, decision, content);
            }

        } catch (Exception e) {
            log.debug("Failed to store in vector database (via cache layer)", e);
        }
    }

    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, String analysisContent) {
        try {
            Map<String, Object> threatMetadata = new HashMap<>();

            // 위협 전용 documentType (Enum 사용)
            threatMetadata.put("documentType", VectorDocumentType.THREAT.getValue());

            // LLM이 직접 결정한 값만 저장
            // AI Native: NaN인 경우 필드 생략
            double riskScore = decision.getRiskScore();
            double confidence = decision.getConfidence();
            if (!Double.isNaN(riskScore)) {
                threatMetadata.put("riskScore", riskScore);
            }
            if (!Double.isNaN(confidence)) {
                threatMetadata.put("confidence", confidence);
            }
            threatMetadata.put("action", decision.getAction().toString());
            // AI Native: null인 경우 필드 생략
            if (decision.getThreatCategory() != null) {
                threatMetadata.put("threatCategory", decision.getThreatCategory());
            }

            // 이벤트 컨텍스트 (Zero Trust 추적성)
            // AI Native: null인 경우 필드 생략, eventType 제거
            if (event.getEventId() != null) {
                threatMetadata.put("eventId", event.getEventId());
            }
            threatMetadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            if (event.getUserId() != null) {
                threatMetadata.put("userId", event.getUserId());
            }
            if (event.getSourceIp() != null) {
                threatMetadata.put("sourceIp", event.getSourceIp());
            }
            if (event.getSessionId() != null) {
                threatMetadata.put("sessionId", event.getSessionId());
            }

            // Layer2 특화 정보: 행동 패턴 (LLM 분석 결과)
            if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
                threatMetadata.put("behaviorPatterns", String.join(", ", decision.getBehaviorPatterns()));
            }

            // 위협 설명 (AI 분석 결과 포함, AI Native: eventType 제거)
            String threatDescription = String.format(
                "Layer1 Contextual Threat: User=%s, IP=%s, RiskScore=%.2f, " +
                "ThreatCategory=%s, BehaviorPatterns=%s, Action=%s, Reasoning=%s",
                event.getUserId(), event.getSourceIp(),
                decision.getRiskScore(), decision.getThreatCategory(),
                decision.getBehaviorPatterns() != null ? decision.getBehaviorPatterns() : "[]",
                decision.getAction(),
                decision.getReasoning() != null ? decision.getReasoning().substring(0, Math.min(100, decision.getReasoning().length())) : ""
            );

            Document threatDoc = new Document(threatDescription, threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

            log.info("[Layer1] 위협 패턴 저장 완료: userId={}, riskScore={}, threatCategory={}, behaviorPatterns={}",
                event.getUserId(), decision.getRiskScore(), decision.getThreatCategory(),
                decision.getBehaviorPatterns() != null ? decision.getBehaviorPatterns().size() : 0);

        } catch (Exception e) {
            log.warn("[Layer1] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }
    @Override
    protected String getLayerName() {
        return "Layer1";
    }

    /**
     * AI Native v3.3.0: MONITOR deprecated
     * - MONITOR_USER_BEHAVIOR 제거
     * - LLM이 결정한 action 기반 권장 조치
     */
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        actions.add("ANALYZE_SESSION_CONTEXT");
        actions.add("CHECK_BEHAVIOR_BASELINE");
        return actions;
    }

    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        log.warn("[Layer1][AI Native] calculateRiskScore called without LLM analysis - returning NaN");
        return Double.NaN;
    }

    /**
     * Action을 권장 조치 문자열로 변환 (AI Native v3.3.0 - 4개 Action)
     */
    private String mapActionToRecommendation(SecurityDecision.Action action) {
        return switch (action) {
            case ALLOW -> "ALLOW";
            case BLOCK -> "BLOCK_IMMEDIATELY";
            case CHALLENGE -> "REQUIRE_MFA";
            case ESCALATE -> "ESCALATE_TO_EXPERT";
        };
    }

    private class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private LocalDateTime startTime;
        private String ipAddress;
        private List<String> recentActions = new ArrayList<>();
        private int accessFrequency = 0;

        public boolean isValid() {
            return startTime != null;
        }

        public void addEvent(SecurityEvent event) {
            accessFrequency++;
            // 설정에서 최대 액션 수 가져오기
            int maxRecentActions = tieredStrategyProperties.getLayer1().getSession().getMaxRecentActions();
            if (recentActions.size() > maxRecentActions) {
                recentActions.remove(0);
            }
            // AI Native: eventType, targetResource 제거 - 행동 기반 기록
            String httpMethod = eventEnricher.getHttpMethod(event).orElse("unknown");
            recentActions.add(httpMethod + ":" + (event.getDescription() != null ? event.getDescription() : "action"));
        }

        public long getSessionDuration() {
            if (startTime == null) return 0;
            return Duration.between(startTime, LocalDateTime.now()).toMinutes();
        }

        // AI Native v4.2.0: getAccessPattern() 삭제 - 프롬프트 미사용

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        // AI Native: "unknown" 기본값 제거, null 그대로 반환
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        // AI Native: "unknown" 기본값 제거, null 그대로 반환
        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }

        // AI Native: "unknown" 기본값 제거, null 그대로 반환
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

        public List<String> getRecentActions() { return recentActions; }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        public int getAccessFrequency() { return accessFrequency; }
        // AI Native v4.3.0: metadata.recentRequestCount로 설정 가능
        public void setAccessFrequency(int accessFrequency) { this.accessFrequency = accessFrequency; }
    }

    private Layer1SecurityResponse validateAndFixResponse(Layer1SecurityResponse response) {
        if (response == null) {
            return createDefaultResponse();
        }

        // AI Native: confidence가 null이면 NaN 사용 (강제 상향 금지)
        if (response.getConfidence() == null) {
            log.warn("[Layer1][AI Native] LLM이 confidence 미반환 (가공 없이 NaN 사용)");
            response.setConfidence(Double.NaN);
        }

        // AI Native: riskScore가 null이면 NaN 사용 (기본값 금지)
        if (response.getRiskScore() == null) {
            log.warn("[Layer1][AI Native] LLM이 riskScore 미반환 (가공 없이 NaN 사용)");
            response.setRiskScore(Double.NaN);
        }

        // AI Native: threatCategory가 null이면 null 유지 (플랫폼 분류 금지)
        // 마커 생성도 AI Native 위반이므로 null 그대로 유지

        // mitigationActions 검증
        if (response.getMitigationActions() == null) {
            response.setMitigationActions(new ArrayList<>());
        }

        return response;
    }

    /**
     * Zero Trust: 세션 컨텍스트 변경 감지 (세션 하이재킹 탐지)
     *
     * 캐시된 세션과 현재 이벤트의 컨텍스트를 비교하여
     * IP 주소 변경을 감지합니다. IP 변경 시 세션 탈취 가능성으로 판단.
     *
     * @param cached 캐시된 SessionContext
     * @param event 현재 SecurityEvent
     * @return IP 변경 시 true (캐시 무효화 필요)
     */
    private boolean isSessionContextChanged(SessionContext cached, SecurityEvent event) {
        String cachedIp = cached.getIpAddress();
        String eventIp = event.getSourceIp();

        // 둘 다 유효한 IP가 있을 때만 비교 (null은 비교 불가로 변경 없음 처리)
        if (cachedIp != null && eventIp != null && !cachedIp.equals(eventIp)) {
            return true;
        }

        return false;
    }

    private static class BehaviorAnalysis {
        private List<String> similarEvents = new ArrayList<>();

        private String baselineContext;
        private boolean baselineEstablished;

        public List<String> getSimilarEvents() { return similarEvents; }
        public void setSimilarEvents(List<String> events) { this.similarEvents = events; }

        public String getBaselineContext() { return baselineContext; }
        public void setBaselineContext(String baselineContext) { this.baselineContext = baselineContext; }

        public boolean isBaselineEstablished() { return baselineEstablished; }
        public void setBaselineEstablished(boolean baselineEstablished) { this.baselineEstablished = baselineEstablished; }
    }
}