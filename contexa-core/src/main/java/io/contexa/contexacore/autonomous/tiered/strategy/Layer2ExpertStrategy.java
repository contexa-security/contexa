package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
// AI Native v4.2.0: FeedbackConstants, FeedbackIntegrationProperties import 삭제 (미사용)
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.response.SecurityResponse;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.soar.approval.ApprovalRequestDetails;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Slf4j

public class Layer2ExpertStrategy extends AbstractTieredStrategy {

    private final UnifiedLLMOrchestrator llmOrchestrator;
    private final ApprovalService approvalService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityEventEnricher eventEnricher;
    private final SecurityPromptTemplate promptTemplate;

    private final BehaviorVectorService behaviorVectorService;
    private final UnifiedVectorService unifiedVectorService;
    private final BaselineLearningService baselineLearningService;
    private final TieredStrategyProperties tieredStrategyProperties;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // AI Native v6.6: L1→L2 프롬프트 컨텍스트 캐시 (동일 요청 내 재사용)
    // Redis 불필요: 동일 JVM 프로세스 내에서 에스컬레이션되므로 메모리 캐시 사용
    private static final Cache<String, SecurityPromptTemplate.SessionContext> SESSION_CONTEXT_CACHE =
        Caffeine.newBuilder()
            .maximumSize(1000)
            .expireAfterWrite(5, java.util.concurrent.TimeUnit.MINUTES)
            .build();

    private static final Cache<String, SecurityPromptTemplate.BehaviorAnalysis> BEHAVIOR_ANALYSIS_CACHE =
        Caffeine.newBuilder()
            .maximumSize(1000)
            .expireAfterWrite(5, java.util.concurrent.TimeUnit.MINUTES)
            .build();

    private static final Cache<String, List<Document>> RAG_DOCUMENTS_CACHE =
        Caffeine.newBuilder()
            .maximumSize(500)
            .expireAfterWrite(5, java.util.concurrent.TimeUnit.MINUTES)
            .build();

    @Value("${spring.ai.security.layer2.model:llama3.1:8b}")
    private String modelName;

    @Value("${spring.ai.security.tiered.layer2.timeout-ms:30000}")
    private long timeoutMs;

    @Value("${spring.ai.security.tiered.layer2.enable-soar:false}")
    private boolean enableSoar;

    @Value("${spring.ai.security.tiered.layer2.rag.top-k:10}")
    private int ragTopK;

    // AI Native v5.1.0: threat-actor-similarity-threshold, campaign-similarity-threshold 삭제
    // - 익명 공격자 탐지용 (플랫폼 역할 아님)

    @Autowired
    public Layer2ExpertStrategy(@Autowired(required = false) UnifiedLLMOrchestrator llmOrchestrator,
                                @Autowired(required = false) ApprovalService approvalService,
                                @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                                @Autowired(required = false) SecurityEventEnricher eventEnricher,
                                @Autowired(required = false) SecurityPromptTemplate promptTemplate,
                                @Autowired(required = false) UnifiedVectorService unifiedVectorService,
                                @Autowired(required = false) BehaviorVectorService behaviorVectorService,
                                @Autowired(required = false) BaselineLearningService baselineLearningService,
                                @Autowired TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.approvalService = approvalService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate : new SecurityPromptTemplate(eventEnricher, tieredStrategyProperties);
        this.behaviorVectorService = behaviorVectorService;
        this.unifiedVectorService = unifiedVectorService;
        this.baselineLearningService = baselineLearningService;
        this.tieredStrategyProperties = tieredStrategyProperties;

        log.info("Layer 2 Expert Strategy initialized with UnifiedLLMOrchestrator");
        log.info("  - Model: {}", modelName);
        log.info("  - Timeout: {}ms", timeoutMs);
        log.info("  - SOAR Integration: {}", enableSoar);
        log.info("  - BaselineLearningService available: {}", baselineLearningService != null);
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.warn("Layer 2 Expert Strategy evaluating event: {}", event.getEventId());

        // AI Native v4.2.0: event metadata에서 Layer2 결과 조회
        SecurityDecision layer2Decision = extractLayer2Decision(event);
        SecurityDecision expertDecision = performDeepAnalysis(event, layer2Decision);
        String action = expertDecision.getAction() != null ? expertDecision.getAction().name() : "ESCALATE";

        // AI Native v5.1.0: iocIndicators 필드 제거 (Layer2SecurityResponse에서 삭제됨)
        // AI Native v8.12: LLM reasoning을 ThreatAssessment에 전달 (TIPS 데모용)
        return ThreatAssessment.builder()
                .riskScore(expertDecision.getRiskScore())
                .confidence(expertDecision.getConfidence())
                .indicators(new ArrayList<>())  // v5.1.0: 빈 리스트 (필드 삭제됨)
                .recommendedActions(List.of(mapActionToRecommendation(expertDecision.getAction())))
                .strategyName("Layer2-Expert")
                .assessedAt(LocalDateTime.now())
                .shouldEscalate(false)  // Layer2는 최종 계층
                .action(action)  // AI Native: LLM action 직접 저장
                .reasoning(expertDecision.getReasoning())  // AI Native v8.12: LLM 분석 근거
                .build();
    }

    /**
     * AI Native v6.6: 전문가 분석 수행
     *
     * L1 = L2 원칙: 동일한 프롬프트 템플릿 사용, 차이점은 LLM 모델만
     * 캐싱: L1에서 수집한 컨텍스트 데이터를 재사용하여 성능 최적화
     */
    public SecurityDecision performDeepAnalysis(SecurityEvent event, SecurityDecision layer2Decision) {
        if (event == null) {
            log.error("Layer 2 analysis failed: event is null");
            return createFailsafeDecision(null, layer2Decision, System.currentTimeMillis());
        }

        if (layer2Decision == null) {
            log.warn("Layer 2 analysis: layer2Decision is null, creating default");
            layer2Decision = createDefaultLayer2Decision();
        }

        long startTime = System.currentTimeMillis();

        try {
            log.warn("[Layer2] Expert Analysis initiated for critical event {}",
                    event.getEventId() != null ? event.getEventId() : "unknown");

            // AI Native v6.6: L1에서 캐싱된 컨텍스트 데이터 재사용
            // L1과 L2는 동일한 프롬프트 데이터를 사용하므로 중복 수집 불필요
            SecurityPromptTemplate.SessionContext sessionCtx = getCachedOrBuildSessionContext(event);
            SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = getCachedOrBuildBehaviorAnalysis(event);
            List<Document> relatedDocuments = getCachedOrSearchRelatedContext(event);

            // AI Native v6.6: 통합 프롬프트 구성 (L1 = L2 동일)
            String promptText = promptTemplate.buildPrompt(event, sessionCtx, behaviorCtx, relatedDocuments);

            SecurityResponse response = null;
            if (llmOrchestrator != null) {
                // AI Native v6.0: temperature=0.0 for deterministic output (consistent LLM responses)
                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(promptText))
                        .tier(2)
                        .preferredModel(modelName)
                        .securityTaskType(ExecutionContext.SecurityTaskType.EXPERT_INVESTIGATION)
                        .timeoutMs((int)timeoutMs)
                        .requestId(event.getEventId())
                        .temperature(0.0)
                        .topP(1.0)  // 결정적 출력을 위한 top-p 파라미터
                        .build();

                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(timeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.warn("[Layer2][AI Native] LLM execution failed, applying failsafe blocking: {}", event.getEventId(), e);
                            // AI Native v6.6: 통합 응답 형식
                            return Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"BLOCK\",\"reasoning\":\"LLM execution failed - failsafe blocking applied\"}");
                        })
                        .block();

                response = parseJsonResponse(jsonResponse);
            } else {
                log.warn("UnifiedLLMOrchestrator not available for Layer 2 analysis");
                response = createDefaultResponse();
            }

            SecurityDecision expertDecision = convertToSecurityDecision(response, event);

            // SOAR 플레이북 실행 (설정에서 활성화된 경우)
            if (enableSoar && expertDecision.getAction() == SecurityDecision.Action.BLOCK) {
                executeSoarPlaybook(expertDecision, event);
            }

            // 승인 프로세스 처리 (필요한 경우)
            if (expertDecision.isRequiresApproval() && approvalService != null) {
                handleApprovalProcess(expertDecision, event);
            }

            // 인시던트 생성 및 알림 (BLOCK 액션인 경우)
            if (expertDecision.getAction() == SecurityDecision.Action.BLOCK) {
                createSecurityIncident(expertDecision, event);
            }

            // 벡터 스토어에 저장 (학습용)
            storeInVectorDatabase(event, expertDecision, response);

            // v3.1.0: MITIGATE -> BLOCK으로 통합됨
            SecurityDecision.Action expertAction = expertDecision.getAction();
            if (expertAction == SecurityDecision.Action.BLOCK) {
                String sourceIp = event.getSourceIp();
                if (sourceIp != null && !sourceIp.isEmpty()) {
                    // 공격 카운트 증가 및 IP 평판 하향
                    incrementAttackCount(sourceIp);
                }
            }

            // 12. 메트릭 업데이트
            expertDecision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            expertDecision.setProcessingLayer(2);

            log.warn("Layer 2 Expert Analysis completed in {}ms - Final Risk: {}, Action: {}",
                    expertDecision.getProcessingTimeMs(),
                    expertDecision.getRiskScore(),
                    expertDecision.getAction() != null ? expertDecision.getAction() : "UNKNOWN");

            return expertDecision;

        } catch (Exception e) {
            log.error("Layer 2 expert analysis failed for event {}",
                    event != null && event.getEventId() != null ? event.getEventId() : "unknown", e);
            return createFailsafeDecision(event, layer2Decision, startTime);
        }
    }

    /**
     * 비동기 전문가 분석
     */
    public Mono<SecurityDecision> performDeepAnalysisAsync(SecurityEvent event,
                                                                                  SecurityDecision layer2Decision) {
        return Mono.fromCallable(() -> performDeepAnalysis(event, layer2Decision))
                .timeout(Duration.ofMillis(timeoutMs))
                .onErrorResume(throwable -> {
                    log.error("Layer 2 async analysis failed or timed out", throwable);
                    return Mono.just(createFailsafeDecision(event, layer2Decision, System.currentTimeMillis()));
                });
    }

    // v5.1.0: gatherThreatIntelligence() 메서드 삭제
    // - 익명 공격자 탐지용 (APT29, Lazarus 등) - 플랫폼 역할 아님
    // - findKnownThreatActors(), identifyRelatedCampaigns() 메서드도 함께 삭제
    // - 플랫폼 핵심: "인증된 사용자가 진짜인가?" 검증
    // - 원본 메서드: Line 258-444 (186줄 삭제)

    /**
     * 과거 컨텍스트 분석
     */
    private HistoricalContext analyzeHistoricalContext(SecurityEvent event) {
        HistoricalContext context = new HistoricalContext();

        // Null safety: event가 null인 경우 기본값 설정
        if (event == null) {
            context.setSimilarIncidents(new ArrayList<>());
            context.setPreviousAttacks(0);
            // AI Native v4.2.0: setVulnerabilityHistory() 삭제 - vulnerabilityHistory 필드 제거됨
            return context;
        }

        // 유사 인시던트 조회 (AI Native: 분류 마커 제거)
        // 빈 리스트는 그대로 전달, LLM이 "정보 없음"을 직접 인식
        List<String> similarIncidents = findSimilarIncidents(event);
        context.setSimilarIncidents(similarIncidents);

        // AI Native v5.1.0: userId 기반 과거 이력 조회
        // 플랫폼 명제: "인증된 사용자가 진짜인가?" 검증
        // - IP 기반이 아닌 userId 기반으로 과거 BLOCK/CHALLENGE 이력 추적
        String userId = event.getUserId();
        int previousBlocks = getPreviousBlocksForUser(userId);
        int previousChallenges = getPreviousChallengesForUser(userId);

        // previousAttacks 필드에 previousBlocks 저장 (호환성 유지)
        // Note: 필드명은 previousAttacks이지만 실제로는 "이 사용자의 과거 BLOCK 횟수"
        context.setPreviousAttacks(previousBlocks);
        context.setPreviousChallenges(previousChallenges);

        return context;
    }

    /**
     * 유사 인시던트 찾기 (Vector-based with fallback)
     * AI Native: eventType, targetResource 제거
     */
    private List<String> findSimilarIncidents(SecurityEvent event) {
        if (behaviorVectorService == null) {
            return findSimilarIncidentsFallback(event);
        }

        try {
            // AI Native v6.8: "unknown" 기본값 제거 - 벡터 임베딩 오염 방지
            // null인 경우 쿼리에서 해당 필드 생략
            StringBuilder incidentQuery = new StringBuilder("security incident");
            if (event.getSourceIp() != null) {
                incidentQuery.append(" from IP:").append(event.getSourceIp());
            }
            String userId = event.getUserId();
            if (userId != null) {
                incidentQuery.append(" user:").append(userId);
            }

            // userId가 null이면 검색 불가 - fallback 사용
            if (userId == null) {
                return findSimilarIncidentsFallback(event);
            }

            // AI Native v8.6: Document-Query 형식 통일
            // - 기존: incidentQuery (텍스트 쿼리) → 문서 형식과 불일치
            // - 변경: User/IP/Path 형식으로 통일
            String sourceIp = event.getSourceIp();
            String requestPath = event.getMetadata() != null ?
                    (String) event.getMetadata().get("requestUri") : null;
            List<Document> similarIncidents = behaviorVectorService.findSimilarBehaviors(
                    userId,
                    sourceIp,
                    requestPath,
                    5
            );

            List<String> incidents = similarIncidents.stream()
                    .map(doc -> {
                        Map<String, Object> meta = doc.getMetadata();
                        String incidentId = meta.getOrDefault("incidentId", "UNKNOWN").toString();
                        String timestamp = meta.getOrDefault("timestamp", "").toString();
                        double similarity = (double) meta.getOrDefault("similarityScore", 0.0);
                        String mitreTactic = meta.getOrDefault("mitreTactic", "").toString();

                        if (!mitreTactic.isEmpty()) {
                            return String.format("Incident %s (%s) [%s] similarity: %.2f",
                                    incidentId, timestamp, mitreTactic, similarity);
                        } else {
                            return String.format("Incident %s (%s) similarity: %.2f",
                                    incidentId, timestamp, similarity);
                        }
                    })
                    .filter(i -> !i.contains("UNKNOWN"))
                    .limit(5)
                    .collect(Collectors.toList());

            if (incidents.isEmpty()) {
                return findSimilarIncidentsFallback(event);
            }

            return incidents;

        } catch (Exception e) {
            log.warn("Vector-based similar incident search failed, using fallback", e);
            return findSimilarIncidentsFallback(event);
        }
    }

    private List<String> findSimilarIncidentsFallback(SecurityEvent event) {
        List<String> incidents = new ArrayList<>();

        // Null safety: event가 null인 경우 빈 리스트 반환
        if (event == null) {
            return incidents;
        }

        if (redisTemplate == null) {
            return incidents;
        }

        // AI Native v6.8: "unknown" 기본값 제거 - userId가 null이면 검색 불가
        String userId = event.getUserId();
        if (userId == null) {
            return incidents;
        }
        String pattern = "incident:*:" + userId;
        int limit = 5;

        try {
            // Redis SCAN: 점진적 스캔으로 블로킹 방지
            ScanOptions scanOptions = ScanOptions.scanOptions()
                    .match(pattern)
                    .count(100)  // 배치 크기 (한 번에 스캔할 키 수)
                    .build();

            try (Cursor<String> cursor = redisTemplate.scan(scanOptions)) {
                while (cursor.hasNext() && incidents.size() < limit) {
                    String key = cursor.next();
                    String[] parts = key.split(":");
                    String incidentId = parts.length > 1 ? parts[1] : key;
                    incidents.add(incidentId);
                }
            }
        } catch (Exception e) {
            log.debug("[Layer2] Failed to find similar incidents via SCAN for user: {}", userId, e);
        }

        return incidents;
    }

    /**
     * AI Native v5.0.0: 세션 컨텍스트 구축 (Layer1과 동일 패턴)
     * Layer2도 원본 데이터를 직접 분석하여 독립적인 검증 수행
     * PRIMARY: SecurityEvent -> SECONDARY: Redis (보강)
     *
     * AI Native v6.0: Zero Trust 세션 하이재킹 탐지 추가
     */
    private BaseSessionContext buildSessionContext(SecurityEvent event) {
        String sessionId = event.getSessionId();

        // PRIMARY SOURCE: SecurityEvent
        // AI Native v6.0: BaseSessionContext 직접 사용 (중복 클래스 제거)
        BaseSessionContext context = new BaseSessionContext();
        context.setSessionId(sessionId);
        context.setUserId(event.getUserId());
        context.setIpAddress(event.getSourceIp());
        context.setStartTime(LocalDateTime.now());

        // AI Native v6.0: authMethod 필드 제거 - AuthorizationDecisionEvent에 해당 필드 없음
        // recentRequestCount 추출 (metadata)
        if (event.getMetadata() != null) {
            Object recentRequestCountObj = event.getMetadata().get("recentRequestCount");
            if (recentRequestCountObj instanceof Number) {
                context.setAccessFrequency(((Number) recentRequestCountObj).intValue());
            }
        }

        // AI Native v6.0: User-Agent 설정 (세션 하이재킹 탐지용)
        // SecurityEvent.userAgent 필드에서 직접 가져옴 (metadata 아님)
        if (event.getUserAgent() != null) {
            context.setUserAgent(event.getUserAgent());
        }

        // SECONDARY SOURCE: Redis (보강만, 실패해도 무시)
        if (sessionId != null && redisTemplate != null) {
            try {
                @SuppressWarnings("unchecked")
                List<String> recentActions = (List<String>) (List<?>) redisTemplate.opsForList()
                        .range(ZeroTrustRedisKeys.sessionActions(sessionId), -10, -1);
                if (recentActions != null && !recentActions.isEmpty()) {
                    context.setRecentActions(recentActions);
                }
            } catch (Exception e) {
                log.debug("[Layer2] Redis enrichment failed: {}", e.getMessage());
            }
        }

        return context;
    }

    /**
     * AI Native v6.0: Zero Trust 세션 컨텍스트 변경 감지 (세션 하이재킹 탐지)
     *
     * AbstractTieredStrategy의 공통 메서드를 호출하여 중복 제거
     *
     * @param event 현재 SecurityEvent
     * @param currentContext 현재 세션 컨텍스트
     * @return 컨텍스트 변경 시 true (세션 하이재킹 가능성)
     */
    private boolean detectSessionContextChange(SecurityEvent event, BaseSessionContext currentContext) {
        if (event == null || currentContext == null) {
            return false;
        }

        // AbstractTieredStrategy의 공통 메서드 호출
        return isSessionContextChangedFromRedis(
            event.getSessionId(),
            currentContext.getIpAddress(),
            currentContext.getUserAgent(),
            redisTemplate
        );
    }

    /**
     * AbstractTieredStrategy 추상 메서드 구현
     * Layer2 유사 이벤트 검색 (벡터 서비스, 폴백 없음)
     */
    @Override
    protected List<String> findSimilarEventsForLayer(SecurityEvent event) {
        return findSimilarEventsForBehavior(event);
    }

    /**
     * AI Native v6.0: 행동 패턴 분석 (AbstractTieredStrategy 공통 메서드 호출)
     * Layer2도 원본 데이터를 직접 분석하여 독립적인 검증 수행
     * - 중복 코드 제거, 공통 로직 재사용
     * - Zero Trust / AI Native 원칙 유지
     */
    private BaseBehaviorAnalysis analyzeBehaviorPatterns(SecurityEvent event) {
        return analyzeBehaviorPatternsBase(event, baselineLearningService);
    }

    /**
     * AI Native v5.0.0: 유사 이벤트 검색 (행동 분석용)
     */
    private List<String> findSimilarEventsForBehavior(SecurityEvent event) {
        if (behaviorVectorService == null) {
            return Collections.emptyList();
        }

        String userId = event.getUserId();
        if (userId == null) {
            log.error("[Layer2][SYSTEM_ERROR] userId null in findSimilarEventsForBehavior");
            return Collections.emptyList();
        }

        // AI Native v8.6: IP/Path로 검색 (Document-Query 형식 100% 통일)
        // - 기존: 한글 쿼리 vs 영어 문서 → 유사도 52%
        // - 변경: 영어 쿼리 = 문서 형식 동일 → 유사도 90%+ 기대
        final String currentIp = event.getSourceIp();
        final Integer currentHour = event.getTimestamp() != null ? event.getTimestamp().getHour() : null;
        final String currentPath = event.getMetadata() != null ?
                (String) event.getMetadata().get("requestUri") : null;

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

                        // Action (과거 결정)
                        String action = meta.get("action") != null ? meta.get("action").toString() : "N/A";

                        // MatchedBy 계산 (어떤 속성이 일치하는지)
                        List<String> matched = new ArrayList<>();
                        if (currentIp != null && currentIp.equals(meta.get("sourceIp"))) {
                            matched.add("IP");
                        }
                        if (currentHour != null && meta.get("timestamp") != null) {
                            String ts = meta.get("timestamp").toString();
                            if (ts.contains("T") && ts.length() > 13) {
                                try {
                                    int docHour = Integer.parseInt(ts.substring(11, 13));
                                    if (currentHour == docHour) {
                                        matched.add("Hour");
                                    }
                                } catch (NumberFormatException ignored) {}
                            }
                        }
                        if (currentPath != null && currentPath.equals(meta.get("requestUri"))) {
                            matched.add("Path");
                        }
                        String matchedBy = matched.isEmpty() ? "Vector" : String.join(",", matched);

                        return String.format("EventID:%s, Similarity:%d%%, Action:%s, MatchedBy:[%s]",
                                meta.get("eventId"), similarityPct, action, matchedBy);
                    })
                    .collect(Collectors.toList());

        } catch (Exception e) {
            log.warn("[Layer2] Similar events search failed", e);
            return Collections.emptyList();
        }
    }

    /**
     * AI Native v6.0: 벡터 스토어에서 관련 문서 검색 (AbstractTieredStrategy 공통 메서드 호출)
     * Layer2도 원본 RAG 데이터를 직접 검색하여 독립적인 분석 수행
     * - 중복 코드 제거, 공통 로직 재사용
     * - AI Native / Zero Trust 원칙 유지
     */
    private List<Document> searchRelatedContext(SecurityEvent event) {
        double similarityThreshold = tieredStrategyProperties.getLayer2().getRag().getSimilarityThreshold();
        return searchRelatedContextBase(event, unifiedVectorService, eventEnricher, ragTopK, similarityThreshold);
    }

    // AI Native v6.6: 변환 메서드 삭제
    // L1 = L2 원칙: 동일한 SecurityPromptTemplate 사용
    // Layer2PromptTemplate.SessionContext, BehaviorAnalysis, HistoricalContext 제거

    /**
     * AI Native v6.6: 캐싱된 세션 컨텍스트 조회 또는 새로 빌드
     *
     * Caffeine 캐시 사용: 동일 JVM 프로세스 내에서 L1→L2 에스컬레이션되므로
     * Redis보다 메모리 캐시가 더 효율적
     */
    private SecurityPromptTemplate.SessionContext getCachedOrBuildSessionContext(SecurityEvent event) {
        String eventId = event.getEventId();

        // 1. Caffeine 캐시에서 조회
        SecurityPromptTemplate.SessionContext cached = SESSION_CONTEXT_CACHE.getIfPresent(eventId);
        if (cached != null) {
            log.debug("[Layer2] Caffeine 캐싱된 SessionContext 사용: eventId={}", eventId);
            return cached;
        }

        // 2. 캐시 미스 - 새로 빌드
        log.debug("[Layer2] SessionContext 캐시 미스, 새로 빌드: eventId={}", eventId);
        BaseSessionContext baseCtx = buildSessionContext(event);

        SecurityPromptTemplate.SessionContext ctx = new SecurityPromptTemplate.SessionContext();
        ctx.setSessionId(baseCtx.getSessionId());
        ctx.setUserId(baseCtx.getUserId());
        ctx.setAuthMethod(baseCtx.getAuthMethod());
        ctx.setRecentActions(baseCtx.getRecentActions());

        return ctx;
    }

    /**
     * AI Native v6.6: 캐싱된 행동 분석 조회 또는 새로 빌드
     *
     * Caffeine 캐시 사용
     */
    private SecurityPromptTemplate.BehaviorAnalysis getCachedOrBuildBehaviorAnalysis(SecurityEvent event) {
        String eventId = event.getEventId();

        // 1. Caffeine 캐시에서 조회
        SecurityPromptTemplate.BehaviorAnalysis cached = BEHAVIOR_ANALYSIS_CACHE.getIfPresent(eventId);
        if (cached != null) {
            log.debug("[Layer2] Caffeine 캐싱된 BehaviorAnalysis 사용: eventId={}", eventId);
            return cached;
        }

        // 2. 캐시 미스 - 새로 빌드
        log.debug("[Layer2] BehaviorAnalysis 캐시 미스, 새로 빌드: eventId={}", eventId);
        BaseBehaviorAnalysis baseAnalysis = analyzeBehaviorPatterns(event);

        SecurityPromptTemplate.BehaviorAnalysis ctx = new SecurityPromptTemplate.BehaviorAnalysis();
        ctx.setSimilarEvents(baseAnalysis.getSimilarEvents());
        ctx.setBaselineContext(baseAnalysis.getBaselineContext());
        ctx.setBaselineEstablished(baseAnalysis.isBaselineEstablished());

        return ctx;
    }

    /**
     * AI Native v6.6: 캐싱된 RAG 문서 조회 또는 새로 검색
     *
     * Caffeine 캐시 사용
     */
    private List<Document> getCachedOrSearchRelatedContext(SecurityEvent event) {
        String eventId = event.getEventId();

        // 1. Caffeine 캐시에서 조회
        List<Document> cached = RAG_DOCUMENTS_CACHE.getIfPresent(eventId);
        if (cached != null) {
            log.debug("[Layer2] Caffeine 캐싱된 RAG 문서 사용: eventId={}, count={}", eventId, cached.size());
            return cached;
        }

        // 2. 캐시 미스 - 새로 검색
        log.debug("[Layer2] RAG 캐시 미스, 새로 검색: eventId={}", eventId);
        return searchRelatedContext(event);
    }

    /**
     * AI Native v6.6: L1에서 컨텍스트 데이터를 캐시에 저장
     *
     * Layer1ContextualStrategy에서 호출하여 L2에서 재사용할 수 있도록 캐싱
     */
    public static void cachePromptContext(String eventId,
                                          SecurityPromptTemplate.SessionContext sessionCtx,
                                          SecurityPromptTemplate.BehaviorAnalysis behaviorCtx,
                                          List<Document> ragDocuments) {
        if (eventId == null) return;

        if (sessionCtx != null) {
            SESSION_CONTEXT_CACHE.put(eventId, sessionCtx);
        }
        if (behaviorCtx != null) {
            BEHAVIOR_ANALYSIS_CACHE.put(eventId, behaviorCtx);
        }
        if (ragDocuments != null && !ragDocuments.isEmpty()) {
            RAG_DOCUMENTS_CACHE.put(eventId, ragDocuments);
        }
    }

    /**
     * 사용자의 과거 BLOCK 횟수 조회 (AI Native v5.1.0)
     *
     * 플랫폼 명제: "인증된 사용자가 진짜인가?" 검증
     * - IP 기반이 아닌 userId 기반으로 과거 이력 추적
     * - 이 사용자가 과거에 몇 번 BLOCK 판정을 받았는지 확인
     *
     * @param userId 사용자 ID
     * @return 과거 BLOCK 횟수 (0 이상)
     */
    private int getPreviousBlocksForUser(String userId) {
        // Null safety: userId가 null인 경우 0 반환
        if (userId == null || userId.trim().isEmpty()) {
            return 0;
        }

        if (redisTemplate == null) {
            return 0;
        }

        try {
            String blockCountKey = ZeroTrustRedisKeys.userBlockCount(userId);
            Object count = redisTemplate.opsForValue().get(blockCountKey);
            if (count != null) {
                return Integer.parseInt(count.toString());
            }
        } catch (Exception e) {
            log.debug("Failed to get previous block count for user: {}", userId, e);
        }

        return 0;
    }

    /**
     * 사용자의 과거 CHALLENGE 횟수 조회 (AI Native v5.1.0)
     *
     * 플랫폼 명제: "인증된 사용자가 진짜인가?" 검증
     * - 이 사용자가 과거에 몇 번 MFA 인증 요청을 받았는지 확인
     *
     * @param userId 사용자 ID
     * @return 과거 CHALLENGE 횟수 (0 이상)
     */
    private int getPreviousChallengesForUser(String userId) {
        // Null safety: userId가 null인 경우 0 반환
        if (userId == null || userId.trim().isEmpty()) {
            return 0;
        }

        if (redisTemplate == null) {
            return 0;
        }

        try {
            String challengeCountKey = ZeroTrustRedisKeys.userChallengeCount(userId);
            Object count = redisTemplate.opsForValue().get(challengeCountKey);
            if (count != null) {
                return Integer.parseInt(count.toString());
            }
        } catch (Exception e) {
            log.debug("Failed to get previous challenge count for user: {}", userId, e);
        }

        return 0;
    }

    /**
     * AI Native v6.6: 응답 검증 (통합 응답 형식)
     * SecurityResponse 필드: riskScore, confidence, action, reasoning, mitre
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

        return response;
    }

    /**
     * AI Native v4.2.0: event metadata에서 Layer1 분석 결과를 추출하여 SecurityDecision으로 변환
     *
     * ColdPathEventProcessor가 Layer1 분석 완료 후 event.metadata에 layer1Assessment를 저장합니다.
     *
     * @param event SecurityEvent (metadata에 layer1Assessment 포함)
     * @return Layer1 분석 결과의 SecurityDecision (없으면 기본 ESCALATE 결정)
     */
    private SecurityDecision extractLayer1Decision(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            log.warn("[Layer2] event or metadata is null, using default Layer1 decision");
            return createDefaultLayer1Decision();
        }

        Object layer1Result = event.getMetadata().get("layer1Assessment");
        if (layer1Result == null) {
            log.debug("[Layer2] No layer1Assessment in metadata, using default Layer1 decision");
            return createDefaultLayer1Decision();
        }

        if (layer1Result instanceof ThreatAssessment layer1Assessment) {
            log.info("[Layer2] Layer1 결과 수신 - riskScore: {}, confidence: {}, action: {}",
                    layer1Assessment.getRiskScore(),
                    layer1Assessment.getConfidence(),
                    layer1Assessment.getAction());

            SecurityDecision.Action action = mapStringToAction(layer1Assessment.getAction());

            return SecurityDecision.builder()
                    .action(action)
                    .riskScore(layer1Assessment.getRiskScore())
                    .confidence(layer1Assessment.getConfidence())
                    .processingTimeMs(50L)
                    .processingLayer(1)
                    .reasoning("Layer1 분석 결과 전달됨")
                    .iocIndicators(layer1Assessment.getIndicators() != null ?
                            layer1Assessment.getIndicators() : new ArrayList<>())
                    .build();
        }

        log.warn("[Layer2] layer1Assessment is not ThreatAssessment type: {}", layer1Result.getClass().getName());
        return createDefaultLayer1Decision();
    }

    /**
     * AI Native v4.2.0: event metadata에서 Layer2 분석 결과를 추출하여 SecurityDecision으로 변환
     *
     * ColdPathEventProcessor가 Layer2 분석 완료 후 event.metadata에 layer2Assessment를 저장합니다.
     *
     * @param event SecurityEvent (metadata에 layer2Assessment 포함)
     * @return Layer2 분석 결과의 SecurityDecision (없으면 기본 ESCALATE 결정)
     */
    private SecurityDecision extractLayer2Decision(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            log.warn("[Layer2] event or metadata is null, using default Layer2 decision");
            return createDefaultLayer2Decision();
        }

        Object layer2Result = event.getMetadata().get("layer2Assessment");
        if (layer2Result == null) {
            log.debug("[Layer2] No layer2Assessment in metadata, using default Layer2 decision");
            return createDefaultLayer2Decision();
        }

        if (layer2Result instanceof ThreatAssessment layer2Assessment) {
            log.info("[Layer2] Layer2 결과 수신 - riskScore: {}, confidence: {}, action: {}",
                    layer2Assessment.getRiskScore(),
                    layer2Assessment.getConfidence(),
                    layer2Assessment.getAction());

            SecurityDecision.Action action = mapStringToAction(layer2Assessment.getAction());

            return SecurityDecision.builder()
                    .action(action)
                    .riskScore(layer2Assessment.getRiskScore())
                    .confidence(layer2Assessment.getConfidence())
                    .processingTimeMs(100L)
                    .processingLayer(2)
                    .reasoning("Layer2 분석 결과 전달됨")
                    .iocIndicators(layer2Assessment.getIndicators() != null ?
                            layer2Assessment.getIndicators() : new ArrayList<>())
                    .build();
        }

        log.warn("[Layer2] layer2Assessment is not ThreatAssessment type: {}", layer2Result.getClass().getName());
        return createDefaultLayer2Decision();
    }

    private SecurityDecision createDefaultLayer1Decision() {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ESCALATE)
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .processingTimeMs(50L)
                .build();
    }

    private SecurityDecision createDefaultLayer2Decision() {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ESCALATE)
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .processingTimeMs(100L)
                .processingLayer(2)
                .build();
    }

    /**
     * AI Native v6.6: SecurityResponse를 SecurityDecision으로 변환
     * SecurityResponse 필드: riskScore, confidence, action, reasoning, mitre
     */
    private SecurityDecision convertToSecurityDecision(SecurityResponse response, SecurityEvent event) {
        // Null safety: response가 null인 경우 기본 응답 생성
        if (response == null) {
            response = createDefaultResponse();
        }

        SecurityDecision.Action action = mapStringToAction(response.getAction());

        // AI Native v6.6: LLM 응답 그대로 사용 (통합 응답 형식)
        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
                .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                .reasoning(response.getReasoning())
                .eventId(event != null ? event.getEventId() : "unknown")
                .analysisTime(System.currentTimeMillis())
                .processingLayer(2)
                .llmModel(modelName)
                .build();

        // AI Native v6.6: MITRE 매핑 (mitre 필드 사용)
        if (response.getMitre() != null && !response.getMitre().isEmpty()) {
            Map<String, String> mitreMapping = new HashMap<>();
            mitreMapping.put(response.getMitre(), response.getMitre());
            decision.setMitreMapping(mitreMapping);
        }

        return decision;
    }

    /**
     * AI Native v6.6: LLM JSON 응답 파싱 (통합 응답 형식)
     * SecurityResponse 필드: riskScore, confidence, action, reasoning, mitre
     */
    private SecurityResponse parseJsonResponse(String jsonResponse) {
        // AI Native v6.6: SecurityResponse.fromJson() 통합 파싱 메서드 사용
        SecurityResponse response = SecurityResponse.fromJson(jsonResponse);
        if (response == null) {
            log.error("Failed to parse JSON response from Layer2 LLM: {}", jsonResponse);
            return createDefaultResponse();
        }
        return validateAndFixResponse(response);
    }

    /**
     * AI Native v6.6: 기본 응답 생성 (통합 응답 형식)
     * SecurityResponse 필드: riskScore, confidence, action, reasoning, mitre
     */
    private SecurityResponse createDefaultResponse() {
        return SecurityResponse.builder()
                .riskScore(Double.NaN)  // AI Native: LLM 분석 미수행
                .confidence(Double.NaN)  // AI Native: LLM 분석 미수행
                .confidenceReasoning(null)  // AI Native v6.3: 분석 미수행
                .action("ESCALATE")
                .reasoning("Layer 2 LLM analysis unavailable")
                .mitre(null)
                .build();
    }

    /**
     * Phase 12: 단축 액션 확장 (A/E/B -> ALLOW/ESCALATE/BLOCK)
     *
     * 통일된 출력 형식에서 사용하는 단축 액션을 긴 형식으로 변환
     */
    private String expandAction(String shortAction) {
        if (shortAction == null) return "ESCALATE";
        return switch (shortAction.toUpperCase()) {
            case "A" -> "ALLOW";
            case "E" -> "ESCALATE";
            case "B" -> "BLOCK";
            default -> shortAction;  // 이미 긴 형식이면 그대로 반환
        };
    }

    // mapStringToAction()은 AbstractTieredStrategy로 이동됨


    /**
     * SOAR 플레이북 실행
     */
    private void executeSoarPlaybook(SecurityDecision decision, SecurityEvent event) {
        if (!enableSoar || decision.getSoarPlaybook() == null) {
            return;
        }

        try {
            log.warn("Executing SOAR playbook: {}", decision.getSoarPlaybook());

            // SOAR 액션 생성 (Map으로 간단히 구현)
            List<Map<String, Object>> actions = new ArrayList<>();

            // 즉시 실행 액션
            if (decision.getAction() == SecurityDecision.Action.BLOCK) {
                Map<String, Object> blockAction = Map.of(
                        "actionType", "BLOCK_IP",
                        "parameters", Map.of("ip", event.getSourceIp())
                );
                actions.add(blockAction);
            }

            // 조사 액션
            if (decision.getIocIndicators() != null && !decision.getIocIndicators().isEmpty()) {
                Map<String, Object> investigateAction = Map.of(
                        "actionType", "INVESTIGATE_IOC",
                        "parameters", Map.of("iocs", decision.getIocIndicators())
                );
                actions.add(investigateAction);
            }

            // 알림 액션
            Map<String, Object> notifyAction = Map.of(
                    "actionType", "NOTIFY_SOC",
                    "parameters", Map.of(
                            "severity", "CRITICAL",
                            "event", event.getEventId(),
                            "risk", decision.getRiskScore()
                    )
            );
            actions.add(notifyAction);

            // Redis에 플레이북 실행 기록
            if (redisTemplate != null) {
                String soarKey = ZeroTrustRedisKeys.soarExecution(event.getEventId());
                redisTemplate.opsForValue().set(
                        soarKey,
                        actions,
                        Duration.ofDays(7)
                );
            }

        } catch (Exception e) {
            log.error("Failed to execute SOAR playbook", e);
        }
    }

    /**
     * 승인 프로세스 처리
     */
    private void handleApprovalProcess(SecurityDecision decision, SecurityEvent event) {
        if (approvalService == null) {
            log.warn("Approval service not available");
            return;
        }

        try {
            // 승인 요청 생성
            SoarContext soarContext = new SoarContext();
            soarContext.setSessionId(event.getEventId());
            soarContext.setOrganizationId("default");
            soarContext.setCreatedAt(LocalDateTime.now());

            Map<String, Object> metadata = Map.of(
                    "riskScore", decision.getRiskScore(),
                    "threatCategory", decision.getThreatCategory() != null ? decision.getThreatCategory() : "UNKNOWN",
                    "action", decision.getAction()
            );

            ApprovalRequestDetails details = new ApprovalRequestDetails(
                    "SOAR_CRITICAL_RESPONSE",
                    "CRITICAL_RESPONSE",
                    "CRITICAL",
                    decision.getExpertRecommendation() != null ? decision.getExpertRecommendation() : "Critical security response required",
                    "event:" + event.getEventId(),
                    metadata
            );

            String approvalId = approvalService.requestApproval(soarContext, details);

            log.warn("Approval requested for critical action on event {}", event.getEventId());

        } catch (Exception e) {
            log.error("Failed to request approval", e);
        }
    }

    /**
     * 보안 인시던트 생성
     */
    private void createSecurityIncident(SecurityDecision decision, SecurityEvent event) {
        try {
            String targetResource = eventEnricher.getTargetResource(event).orElse("unknown");

            SecurityIncident incident = SecurityIncident.builder()
                    .incidentId("L3-" + event.getEventId())
                    .type(SecurityIncident.IncidentType.INTRUSION_ATTEMPT)
                    .threatLevel(SecurityIncident.ThreatLevel.CRITICAL)
                    .status(SecurityIncident.IncidentStatus.CONFIRMED)
                    .description(decision.getAttackScenario())
                    .sourceIp(event.getSourceIp())
                    .detectedBy("Layer2ExpertSystem")
                    .detectionSource("Expert AI Analysis")
                    .detectedAt(LocalDateTime.now())
                    .riskScore(decision.getRiskScore())
                    .autoResponseEnabled(true)
                    .requiresApproval(decision.isRequiresApproval())
                    .build();

            if (redisTemplate != null) {
                String incidentKey = ZeroTrustRedisKeys.incident(incident.getIncidentId());
                redisTemplate.opsForValue().set(
                        incidentKey,
                        incident,
                        Duration.ofDays(30)
                );
            }

            log.warn("Security Incident created: {}", incident.getIncidentId());

        } catch (Exception e) {
            log.error("Failed to create security incident", e);
        }
    }

    private SecurityDecision createFailsafeDecision(SecurityEvent event,
                                                    SecurityDecision layer2Decision,
                                                    long startTime) {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.BLOCK)  // 안전을 위해 차단
                .riskScore(Double.NaN)  // AI Native: LLM 분석 미수행
                .confidence(Double.NaN)  // AI Native: LLM 분석 미수행
                .analysisTime(startTime)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .processingLayer(2)
                .eventId(event != null ? event.getEventId() : "unknown")
                .reasoning("[AI Native] Layer 2 LLM analysis failed - applying failsafe blocking")
                .requiresApproval(true)
                .expertRecommendation("Manual review required - LLM analysis failed")
                .build();
    }

    // v5.1.0: ThreatIntelligence 내부 클래스 삭제
    // - 익명 공격자 탐지용 (APT29, Lazarus 등) - 플랫폼 역할 아님
    // - gatherThreatIntelligence(), findKnownThreatActors(), identifyRelatedCampaigns() 메서드와 함께 삭제
    // - 플랫폼 핵심: "인증된 사용자가 진짜인가?" 검증

    /**
     * AI Native v4.2.0: vulnerabilityHistory 필드 삭제
     * - 프롬프트에 전달되지 않음 (getter 호출 없음)
     * - Line 156, 462 주석: "AI Native: vulnerabilityHistory는 항상 빈 리스트"
     */
    /**
     * AI Native v5.1.0: 과거 이력 컨텍스트
     *
     * 플랫폼 명제: "인증된 사용자가 진짜인가?" 검증
     * - previousAttacks: 이 사용자의 과거 BLOCK 횟수 (IP가 아닌 userId 기반)
     * - previousChallenges: 이 사용자의 과거 CHALLENGE 횟수
     */
    private static class HistoricalContext {
        private List<String> similarIncidents = new ArrayList<>();
        private int previousAttacks;  // userId 기반 과거 BLOCK 횟수
        private int previousChallenges;  // userId 기반 과거 CHALLENGE 횟수

        // Getters and setters
        public List<String> getSimilarIncidents() { return similarIncidents; }
        public void setSimilarIncidents(List<String> incidents) { this.similarIncidents = incidents; }

        public int getPreviousAttacks() { return previousAttacks; }
        public void setPreviousAttacks(int count) { this.previousAttacks = count; }

        public int getPreviousChallenges() { return previousChallenges; }
        public void setPreviousChallenges(int count) { this.previousChallenges = count; }
    }

    // AI Native v6.0: SessionContext 클래스 삭제 - AbstractTieredStrategy.BaseSessionContext 사용
    // AI Native v6.0: BehaviorAnalysis 클래스 삭제 - AbstractTieredStrategy.BaseBehaviorAnalysis 사용

    /**
     * AbstractTieredStrategy의 getLayerName() 구현
     */
    @Override
    protected String getLayerName() {
        return "Layer2";
    }

    @Override
    public String getStrategyName() {
        return "Layer2-Expert-Strategy";
    }

    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        // ThreatIndicator 추출 로직
        return new ArrayList<>();
    }

    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        actions.add("INITIATE_INCIDENT_RESPONSE");
        actions.add("PERFORM_FORENSIC_ANALYSIS");
        actions.add("ENGAGE_SOAR_PLAYBOOK");
        return actions;
    }

    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        // AI Native: LLM이 직접 분석해야 함, 규칙 기반 계산 금지
        log.warn("[Layer2][AI Native] calculateRiskScore called without LLM - returning NaN");
        return Double.NaN;
    }

    /**
     * Action을 권장 조치 문자열로 변환 (AI Native v3.3.0 - 4개 Action)
     */
    private String mapActionToRecommendation(SecurityDecision.Action action) {
        return switch (action) {
            case ALLOW -> "ALLOW_WITH_MONITORING";
            case BLOCK -> "BLOCK_WITH_INCIDENT_RESPONSE";
            case CHALLENGE -> "REQUIRE_REAUTHENTICATION";
            case ESCALATE -> "ESCALATE_TO_SOC";
        };
    }

    // AI Native v4.2.0: buildSystemContext() 메서드 삭제
    // - asset.criticality, data.sensitivity, compliance.requirements, security.posture
    //   모두 metadata에 설정 코드 없음 (항상 null, 죽은 데이터)
    // - Layer2PromptTemplate.SystemContext 클래스도 삭제됨

    /**
     * AI Native v8.6: 벡터 데이터베이스에 저장 (Document-Query 형식 통일)
     *
     * Document Content 형식: "User: admin, IP: 0:0:0:0:0:0:0:1, Path: /api/users"
     * SecurityDecisionPostProcessor.buildBehaviorContent()와 100% 동일한 형식
     */
    private void storeInVectorDatabase(SecurityEvent event, SecurityDecision decision, SecurityResponse response) {
        if (unifiedVectorService == null) return;

        try {
            // AI Native v8.6: Document-Query 형식 100% 통일 (Similarity 95%+ 목표)
            // SecurityDecisionPostProcessor.buildBehaviorContent()와 동일한 형식
            // - User, IP, Path만 포함 (검색 쿼리와 일치)
            // - MITRE 제거 (BEHAVIOR 문서에서) - THREAT 문서에서만 사용
            StringBuilder content = new StringBuilder();

            // User (검색 키 - Query와 일치)
            if (event.getUserId() != null) {
                content.append("User: ").append(event.getUserId());
            }

            // IP (검색 키 - Query와 일치)
            if (event.getSourceIp() != null) {
                if (content.length() > 0) content.append(", ");
                content.append("IP: ").append(event.getSourceIp());
            }

            // Path (검색 키 - Query와 일치)
            String path = eventEnricher.getTargetResource(event).orElse(null);
            if (path != null && !path.isEmpty()) {
                if (content.length() > 0) content.append(", ");
                content.append("Path: ").append(path);
            }

            // AI Native v8.6: MITRE 제거 (BEHAVIOR 문서에서)
            // - MITRE는 THREAT 문서(storeThreatDocument)에서만 사용
            // - BEHAVIOR 문서는 검색 쿼리와 일치하는 User, IP, Path만 포함

            // Spring AI Document는 null 값을 허용하지 않으므로 기본값 설정 필수
            Map<String, Object> metadata = new HashMap<>();

            // 필수 공통 metadata
            metadata.put("documentType", VectorDocumentType.BEHAVIOR.getValue());
            if (event.getEventId() != null) {
                metadata.put("eventId", event.getEventId());
            }
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            if (event.getUserId() != null) {
                metadata.put("userId", event.getUserId());
            }

            // SecurityEvent 정보
            if (event.getSourceIp() != null) {
                metadata.put("sourceIp", event.getSourceIp());
            }
            if (event.getSessionId() != null) {
                metadata.put("sessionId", event.getSessionId());
            }

            // AI Native v7.0: action, riskScore, confidence 모두 제거 (순환 로직 방지)
            // LLM 결과(action 포함)가 다음 분석에 영향을 미치면 독립적 분석 불가
            // action 저장 제거: 이전 BLOCK/ALLOW가 다음 판단에 편향을 줄 수 있음
            // threatCategory만 유지 (위협 유형 분류는 참조용으로 허용)
            if (decision.getThreatCategory() != null) {
                metadata.put("threatCategory", decision.getThreatCategory());
            }

            // v5.1.0: MITRE 정보 (mitre 필드 사용)
            if (response.getMitre() != null && !response.getMitre().isEmpty()) {
                metadata.put("mitreTactic", response.getMitre());
            }

            Document document = new Document(content.toString(), metadata);
            unifiedVectorService.storeDocument(document);

            // v3.1.0: MITIGATE -> BLOCK으로 통합됨
            SecurityDecision.Action storeAction = decision.getAction();
            if (storeAction == SecurityDecision.Action.BLOCK) {
                storeThreatDocument(event, decision, response, content.toString());
            }

        } catch (Exception e) {
            log.debug("Failed to store in vector database", e);
        }
    }

    /**
     * AI Native v7.0: 위협 문서 저장 (순환 로직 방지)
     *
     * - LLM 결과(riskScore, reasoning, action) 제거 - 이전 분석이 다음 분석에 영향을 미치면 안 됨
     * - "unknown" 기본값 제거 - LLM이 실제 값으로 오해, 벡터 임베딩 오염
     * - 사실 데이터만 포함 (userId, sourceIp, MITRE)
     */
    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, SecurityResponse response, String analysisContent) {
        try {
            // AI Native v6.0: AbstractTieredStrategy.buildBaseMetadata() 공통 메서드 활용
            Map<String, Object> threatMetadata = buildBaseMetadata(event, decision, VectorDocumentType.THREAT.getValue());

            // v5.1.0: MITRE 정보 (Layer2 특화 필드)
            if (response.getMitre() != null && !response.getMitre().isEmpty()) {
                threatMetadata.put("mitreTactic", response.getMitre());
            }

            // AI Native v7.0: 위협 설명 - 사실 데이터만 포함, LLM 결과(riskScore, reasoning, action) 제거
            StringBuilder threatDesc = new StringBuilder("Layer2 Expert Threat:");
            if (event.getUserId() != null) {
                threatDesc.append(" User=").append(event.getUserId());
            }
            if (event.getSourceIp() != null) {
                threatDesc.append(", IP=").append(event.getSourceIp());
            }
            if (response.getMitre() != null && !response.getMitre().isEmpty()) {
                threatDesc.append(", MITRE=").append(response.getMitre());
            }
            // AI Native v7.0: action 제거 (LLM 결과 = 순환 로직)
            // 이전: threatDesc.append(", Action=").append(decision.getAction());
            // AI Native v7.0: riskScore, reasoning, action 모두 제거 (순환 로직 방지)

            Document threatDoc = new Document(threatDesc.toString(), threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

            log.info("[Layer2] 위협 패턴 저장 완료: userId={}, mitre={}",
                event.getUserId(), response.getMitre());

        } catch (Exception e) {
            log.warn("[Layer2] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }

    // v5.1.0: determineThreatType() 메서드 삭제
    // - response.getClassification() 필드 제거됨
    // - LLM이 classification을 반환하지 않으므로 불필요
    private void incrementAttackCount(String sourceIp) {
        if (redisTemplate == null || sourceIp == null || sourceIp.isEmpty()) {
            return;
        }

        try {
            String attackCountKey = ZeroTrustRedisKeys.attackCount(sourceIp);
            Long count = redisTemplate.opsForValue().increment(attackCountKey);
            redisTemplate.expire(attackCountKey, Duration.ofDays(7));
            log.debug("Incremented attack count: ip={}, count={}", sourceIp, count);

        } catch (Exception e) {
            log.debug("Failed to increment attack count: ip={}", sourceIp, e);
        }
    }
}