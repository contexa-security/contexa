package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.response.SecurityResponse;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
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
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j

public class Layer1ContextualStrategy extends AbstractTieredStrategy {

    private final UnifiedLLMOrchestrator llmOrchestrator;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityEventEnricher eventEnricher;
    private final SecurityPromptTemplate promptTemplate;
    private final BehaviorVectorService behaviorVectorService;
    private final UnifiedVectorService unifiedVectorService;
    private final BaselineLearningService baselineLearningService;
    private final TieredStrategyProperties tieredStrategyProperties;
    private final SecurityDecisionPostProcessor postProcessor;
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
                                    @Autowired(required = false) SecurityPromptTemplate promptTemplate,
                                    @Autowired(required = false) BehaviorVectorService behaviorVectorService,
                                    @Autowired(required = false) BaselineLearningService baselineLearningService,
                                    @Autowired(required = false) SecurityDecisionPostProcessor postProcessor,
                                    @Autowired TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.unifiedVectorService = unifiedVectorService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate : new SecurityPromptTemplate(eventEnricher, tieredStrategyProperties);
        this.behaviorVectorService = behaviorVectorService;
        this.baselineLearningService = baselineLearningService;
        this.postProcessor = postProcessor;
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
            BaseBehaviorAnalysis behaviorAnalysis = analyzeBehaviorPatterns(event);

            // 3. 벡터 스토어에서 관련 컨텍스트 검색
            List<Document> relatedDocuments = searchRelatedContext(event);

            // 4. PromptTemplate을 통한 프롬프트 구성
            SecurityPromptTemplate.SessionContext sessionCtx = convertToTemplateSessionContext(sessionContext);
            // AI Native v8.9: SecurityEvent 파라미터 추가 (OS 필드 설정용)
            SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = convertToTemplateBehaviorAnalysis(behaviorAnalysis, event);

            String promptText = promptTemplate.buildPrompt(event, sessionCtx, behaviorCtx, relatedDocuments);

            // AI Native v4.3.0: 설정에서 타임아웃 가져오기
            long llmTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getLlmMs();

            SecurityResponse response = null;
            if (llmOrchestrator != null) {
                // AI Native v6.0: temperature=0.0 for deterministic output (consistent LLM responses)
                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(promptText))
                        .tier(1)
                        .preferredModel(modelName)
                        .securityTaskType(ExecutionContext.SecurityTaskType.CONTEXTUAL_ANALYSIS)
                        .timeoutMs((int)llmTimeoutMs)
                        .requestId(event.getEventId())
                        .temperature(0.0)
                        .topP(1.0)  // 결정적 출력을 위한 top-p 파라미터
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

            // AI Native v6.6: ESCALATE 시 L2를 위한 컨텍스트 캐싱
            // L1과 L2는 동일한 프롬프트 데이터를 사용하므로 중복 수집 방지
            if (decision.getAction() == SecurityDecision.Action.ESCALATE) {
                Layer2ExpertStrategy.cachePromptContext(
                    event.getEventId(), sessionCtx, behaviorCtx, relatedDocuments);
                log.debug("[Layer1] ESCALATE - L2를 위한 컨텍스트 캐싱 완료: eventId={}", event.getEventId());
            }

            // 6. 메타데이터 추가
            enrichDecisionWithContext(decision, sessionContext, behaviorAnalysis);
            decision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            decision.setProcessingLayer(1);

            // 7. 세션 컨텍스트 업데이트 (AI Native v6.8: 공통 서비스 사용)
            if (postProcessor != null) {
                postProcessor.updateSessionContext(event, decision);
            }

            // 8. 벡터 스토어에 저장 (학습용) (AI Native v6.8: 공통 서비스 사용)
            if (postProcessor != null) {
                postProcessor.storeInVectorDatabase(event, decision);
            }

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

        // AI Native v6.0: metadata에서 authMethod, recentRequestCount 추출
        // ZeroTrustEventListener.java:610에서 "authMethod" 키로 저장됨
        if (event.getMetadata() != null) {
            // authMethod 추출 (Zero Trust: 인증 방식은 위험 판단의 핵심 정보)
            Object authMethodObj = event.getMetadata().get("authMethod");
            if (authMethodObj instanceof String) {
                context.setAuthMethod((String) authMethodObj);
            }
            // AI Native v4.3.0: metadata.recentRequestCount를 accessFrequency로 사용
            // HCADFilter에서 Redis 기반으로 정확하게 추적한 값이므로 SessionContext 내부 카운터보다 신뢰도 높음
            Object recentRequestCountObj = event.getMetadata().get("recentRequestCount");
            if (recentRequestCountObj instanceof Number) {
                context.setAccessFrequency(((Number) recentRequestCountObj).intValue());
            }
        }

        // AI Native v6.0: User-Agent 설정 (세션 하이재킹 탐지용)
        if (event.getUserAgent() != null) {
            context.setUserAgent(event.getUserAgent());
        }

        // SECONDARY SOURCE: Redis (보강만, 실패해도 무시)
        // AI Native v6.0: CompletableFuture 제거 - Redis 클라이언트 레벨 타임아웃 사용
        // spring.data.redis.timeout 설정으로 타임아웃 관리
        if (sessionId != null && redisTemplate != null) {
            try {
                @SuppressWarnings("unchecked")
                List<String> recentActions = (List<String>) (List<?>) redisTemplate.opsForList()
                        .range(ZeroTrustRedisKeys.sessionActions(sessionId), -10, -1);
                if (recentActions != null && !recentActions.isEmpty()) {
                    context.setRecentActions(recentActions);
                }
            } catch (Exception e) {
                log.debug("[Layer1] Redis enrichment failed: {}", e.getMessage());
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
     * AbstractTieredStrategy 추상 메서드 구현
     * Layer1 유사 이벤트 검색 (벡터 서비스 + Redis SCAN 폴백)
     */
    @Override
    protected List<String> findSimilarEventsForLayer(SecurityEvent event) {
        return findSimilarEvents(event);
    }

    /**
     * 행동 패턴 분석
     *
     * AI Native v6.0: AbstractTieredStrategy.analyzeBehaviorPatternsBase() 호출로 통합
     * - 중복 코드 제거, 공통 로직 재사용
     * - Zero Trust / AI Native 원칙 유지
     */
    private BaseBehaviorAnalysis analyzeBehaviorPatterns(SecurityEvent event) {
        return analyzeBehaviorPatternsBase(event, baselineLearningService);
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

        // AI Native v8.6: IP/Path로 검색 (Document-Query 형식 100% 통일)
        // - 기존: 한글 쿼리 "사용자 admin의 활동 패턴" vs 영어 문서 "User: admin, IP: x.x.x.x"
        // - 변경: 영어 쿼리 "User: admin, IP: x.x.x.x, Path: /api/xxx" = 문서 형식 동일
        // - 효과: 유사도 52% -> 90%+ 기대
        final String currentIp = event.getSourceIp();
        final Integer currentHour = event.getTimestamp() != null ? event.getTimestamp().getHour() : null;
        // AI Native v8.10: requestPath로 통일 (HCADContext 도메인 객체 기준)
        final String currentPath = event.getMetadata() != null ?
                (String) event.getMetadata().get("requestPath") : null;

        try {
            List<Document> similarBehaviors = behaviorVectorService.findSimilarBehaviors(
                    userId,
                    currentIp,
                    currentPath,
                    5
            );

            return similarBehaviors.stream()
                    .map(doc -> {
                        Map<String, Object> meta = doc.getMetadata();

                        // Similarity 계산 (0.0-1.0 -> %)
                        double score = 0.0;
                        Object scoreObj = meta.get("similarityScore");
                        if (scoreObj instanceof Number) {
                            score = ((Number) scoreObj).doubleValue();
                        }
                        int similarityPct = (int) (score * 100);

                        // AI Native v7.0: Path 추출
                        String docPath = meta.get("requestUri") != null ?
                                meta.get("requestUri").toString() : "N/A";

                        // AI Native v7.0: IP MATCH/MISMATCH 명시
                        String ipMatch;
                        Object docIp = meta.get("sourceIp");
                        if (docIp == null) {
                            ipMatch = "N/A";
                        } else if (currentIp != null && currentIp.equals(docIp.toString())) {
                            ipMatch = "MATCH";
                        } else {
                            ipMatch = "MISMATCH";
                        }

                        // AI Native v7.0: Hour MATCH/MISMATCH 명시
                        String hourMatch = "N/A";
                        if (currentHour != null && meta.get("timestamp") != null) {
                            String ts = meta.get("timestamp").toString();
                            if (ts.contains("T") && ts.length() > 13) {
                                try {
                                    int docHour = Integer.parseInt(ts.substring(11, 13));
                                    hourMatch = (currentHour == docHour) ? "MATCH" : "MISMATCH";
                                } catch (NumberFormatException ignored) {
                                    hourMatch = "N/A";
                                }
                            }
                        }

                        // AI Native v7.0: Path MATCH/MISMATCH 명시
                        String pathMatch;
                        if (docPath.equals("N/A")) {
                            pathMatch = "N/A";
                        } else if (currentPath != null && currentPath.equals(docPath)) {
                            pathMatch = "MATCH";
                        } else {
                            pathMatch = "MISMATCH";
                        }

                        return String.format("EventID:%s, Similarity:%d%%, Path:%s, IP:%s, Hour:%s, PathMatch:%s",
                                meta.get("eventId"), similarityPct, docPath, ipMatch, hourMatch, pathMatch);
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
     *
     * AI Native v6.0: AbstractTieredStrategy.searchRelatedContextBase() 호출로 통합
     * - 중복 코드 제거, 공통 로직 재사용
     * - AI Native / Zero Trust 원칙 유지
     */
    private List<Document> searchRelatedContext(SecurityEvent event) {
        double similarityThreshold = tieredStrategyProperties.getLayer1().getRag().getSimilarityThreshold();
        int topK = Math.min(15, vectorSearchLimit * 2);
        return searchRelatedContextBase(event, unifiedVectorService, eventEnricher, topK, similarityThreshold);
    }

    /**
     * SessionContext 변환
     *
     * AI Native v6.6: SESSION 의미화
     * - sessionAgeMinutes: 세션 시작 후 경과 시간 (분)
     * - requestCount: 현재 세션의 요청 횟수
     */
    private SecurityPromptTemplate.SessionContext convertToTemplateSessionContext(SessionContext sessionContext) {
        SecurityPromptTemplate.SessionContext ctx = new SecurityPromptTemplate.SessionContext();
        ctx.setSessionId(sessionContext.getSessionId());
        ctx.setUserId(sessionContext.getUserId());
        ctx.setAuthMethod(sessionContext.getAuthMethod());
        ctx.setRecentActions(sessionContext.getRecentActions());

        // AI Native v6.6: SESSION 의미화 - LLM에 유용한 컨텍스트 제공
        // 세션 경과 시간 계산
        if (sessionContext.getStartTime() != null) {
            long minutes = java.time.Duration.between(
                sessionContext.getStartTime(),
                java.time.LocalDateTime.now()
            ).toMinutes();
            ctx.setSessionAgeMinutes((int) Math.max(0, minutes));
        }
        // 요청 횟수
        ctx.setRequestCount(sessionContext.getAccessFrequency());

        return ctx;
    }

    /**
     * AI Native v8.9: SecurityEvent 파라미터 추가
     * - currentUserAgentOS: 현재 요청의 OS (event.getUserAgent()에서 추출)
     * - previousUserAgentOS: Baseline의 OS (baselineContext에서 추출)
     */
    private SecurityPromptTemplate.BehaviorAnalysis convertToTemplateBehaviorAnalysis(
            BaseBehaviorAnalysis behaviorAnalysis,
            SecurityEvent event) {
        SecurityPromptTemplate.BehaviorAnalysis ctx = new SecurityPromptTemplate.BehaviorAnalysis();

        ctx.setSimilarEvents(behaviorAnalysis.getSimilarEvents());
        ctx.setBaselineContext(behaviorAnalysis.getBaselineContext());
        ctx.setBaselineEstablished(behaviorAnalysis.isBaselineEstablished());

        // AI Native v8.9: UserAgent OS 필드 설정 (LLM이 디바이스 변경 패턴 분석용)
        // 1. 현재 요청의 UserAgent OS
        if (event != null && event.getUserAgent() != null) {
            String currentOS = extractOSFromUserAgent(event.getUserAgent());
            ctx.setCurrentUserAgentOS(currentOS);
        }

        // 2. Baseline의 UserAgent OS (baselineContext에서 추출)
        if (behaviorAnalysis.getBaselineContext() != null) {
            String baselineOS = extractOSFromBaselineContext(behaviorAnalysis.getBaselineContext());
            ctx.setPreviousUserAgentOS(baselineOS);
        }

        return ctx;
    }

    /**
     * AI Native v8.9: Baseline 컨텍스트에서 UserAgent OS 추출
     *
     * JSON 형식: "ua": {"status": "...", "current": "Chrome/120 (Android)", "baseline": "Chrome/143 (Windows)"}
     */
    private String extractOSFromBaselineContext(String baselineContext) {
        if (baselineContext == null || baselineContext.isEmpty()) {
            return null;
        }

        try {
            // "baseline": "Chrome/143 (Windows)" 패턴에서 OS 추출
            int baselineIdx = baselineContext.indexOf("\"baseline\":");
            if (baselineIdx == -1) return null;

            int startParen = baselineContext.indexOf("(", baselineIdx);
            int endParen = baselineContext.indexOf(")", startParen);

            if (startParen != -1 && endParen != -1 && endParen > startParen) {
                return baselineContext.substring(startParen + 1, endParen);
            }
        } catch (Exception e) {
            log.debug("[Layer1] Failed to extract OS from baseline context: {}", e.getMessage());
        }

        return null;
    }

    /**
     * AI Native v6.6: SecurityResponse를 SecurityDecision으로 변환
     *
     * 통합된 응답 형식 (5필드):
     * - riskScore, confidence, action, reasoning, mitre
     * - threatCategory, mitigationActions 등은 제거됨 (프롬프트 미요청)
     */
    private SecurityDecision convertToSecurityDecision(SecurityResponse response,
                                                       SecurityEvent event) {
        SecurityDecision.Action action = mapStringToAction(response.getAction());

        // AI Native: Layer1 점수 폴백 금지 - LLM이 분석 못하면 NaN
        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
                .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                .reasoning(response.getReasoning())
                .eventId(event.getEventId())
                .analysisTime(System.currentTimeMillis())
                .build();

        // AI Native v6.6: mitre 필드를 threatCategory로 매핑 (호환성 유지)
        if (response.getMitre() != null && !response.getMitre().isBlank()) {
            decision.setThreatCategory(response.getMitre());
        }

        return decision;
    }

    /**
     * AI Native v6.6: JSON 응답 파싱
     *
     * SecurityResponse.fromJson()을 사용하여 축약/전체 JSON 모두 지원
     * - 축약 형식: {"r":0.75,"c":0.85,"a":"E","d":"..."}
     * - 전체 형식: {"riskScore":0.75,"confidence":0.85,"action":"ESCALATE","reasoning":"..."}
     */
    private SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            // JSON 문자열에서 {}만 추출
            String cleanedJson = extractJsonObject(jsonResponse);

            // SecurityResponse.fromJson()으로 파싱 (축약/전체 모두 지원)
            SecurityResponse response = SecurityResponse.fromJson(cleanedJson);

            if (response != null && response.isValid()) {
                log.debug("[Layer1] JSON 파싱 성공: {}", cleanedJson);
                return validateAndFixResponse(response);
            }

            log.warn("[Layer1] JSON 파싱 실패, 기본 응답 반환: {}", cleanedJson);
            return createDefaultResponse();

        } catch (Exception e) {
            log.error("[Layer1] JSON 응답 파싱 실패: {}", jsonResponse, e);
            return createDefaultResponse();
        }
    }

    /**
     * AI Native v6.6: 기본 응답 생성
     *
     * LLM 분석 불가 시 ESCALATE로 상위 Layer에 위임
     */
    private SecurityResponse createDefaultResponse() {
        return SecurityResponse.builder()
                .riskScore(null)  // AI Native: NaN 대신 null (fromJson 호환성)
                .confidence(null)
                .action("ESCALATE")
                .reasoning("[AI Native] Layer 1 LLM analysis unavailable - escalating to Layer 2")
                .mitre(null)
                .build();
    }

    // mapStringToAction()은 AbstractTieredStrategy로 이동됨

    /**
     * 결정에 컨텍스트 정보 추가
     */
    private void enrichDecisionWithContext(SecurityDecision decision,
                                           SessionContext sessionContext,
                                           BaseBehaviorAnalysis behaviorAnalysis) {

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

    // AI Native v6.8: updateSessionContext(), storeInVectorDatabase() 메서드 삭제
    // - SecurityDecisionPostProcessor 서비스로 이동
    // - 코드 중복 제거, ZeroTrustEventListener와 일관성 유지
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

    /**
     * AI Native v6.0: BaseSessionContext를 확장한 Layer1 전용 SessionContext
     *
     * BaseSessionContext의 모든 필드와 메서드를 상속받고,
     * Layer1 전용 기능인 addEvent()만 추가합니다.
     *
     * 공통화 효과:
     * - 중복 코드 ~60줄 제거
     * - 세션 하이재킹 탐지 로직 통합
     */
    private class SessionContext extends BaseSessionContext {

        /**
         * Layer1 전용: 이벤트 발생 시 세션 컨텍스트 업데이트
         *
         * - accessFrequency 증가
         * - recentActions에 행동 기록 추가
         *
         * @param event SecurityEvent
         */
        public void addEvent(SecurityEvent event) {
            accessFrequency++;
            // 설정에서 최대 액션 수 가져오기
            int maxRecentActions = tieredStrategyProperties.getLayer1().getSession().getMaxRecentActions();
            if (recentActions.size() > maxRecentActions) {
                recentActions.remove(0);
            }
            // AI Native v6.0: httpMethod 제거 - LLM 분석에 불필요 (Description에서 유추 가능)
            recentActions.add(event.getDescription() != null ? event.getDescription() : "action");
        }
    }

    /**
     * AI Native v6.6: 응답 검증 및 수정
     *
     * 통합된 SecurityResponse 형식 검증
     */
    private SecurityResponse validateAndFixResponse(SecurityResponse response) {
        if (response == null) {
            return createDefaultResponse();
        }

        // AI Native v6.0: AbstractTieredStrategy.validateResponseBase() 공통 메서드 활용
        // - 중복 코드 제거, AI Native 원칙 일관성 유지
        // - null인 경우 NaN으로 변환 (플랫폼이 임의 값 설정 금지)
        double[] validated = validateResponseBase(response.getRiskScore(), response.getConfidence());
        response.setRiskScore(validated[0]);
        response.setConfidence(validated[1]);

        // AI Native v6.6: action이 null이면 ESCALATE로 설정
        if (response.getAction() == null || response.getAction().isBlank()) {
            response.setAction("ESCALATE");
            log.warn("[Layer1][Fallback] action 누락, ESCALATE로 설정");
        }

        return response;
    }

    // AI Native v6.0: isSessionContextChanged() 삭제
    // - SessionContext가 BaseSessionContext를 extends
    // - AbstractTieredStrategy.isSessionContextChanged(BaseSessionContext, SecurityEvent) 공통 메서드 사용
    // - 세션 하이재킹 탐지 로직 통합 완료

    // AI Native v6.0: BehaviorAnalysis 클래스 삭제 - AbstractTieredStrategy.BaseBehaviorAnalysis 사용
}