package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
// AI Native v4.2.0: FeedbackConstants, FeedbackIntegrationProperties import 삭제 (미사용)
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.response.Layer2SecurityResponse;
import io.contexa.contexacore.autonomous.tiered.template.Layer2PromptTemplate;
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
    private final Layer2PromptTemplate promptTemplate;

    private final BehaviorVectorService behaviorVectorService;
    private final UnifiedVectorService unifiedVectorService;
    private final BaselineLearningService baselineLearningService;
    private final TieredStrategyProperties tieredStrategyProperties;
    private final ObjectMapper objectMapper = new ObjectMapper();

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
                                @Autowired(required = false) Layer2PromptTemplate promptTemplate,
                                @Autowired(required = false) UnifiedVectorService unifiedVectorService,
                                @Autowired(required = false) BehaviorVectorService behaviorVectorService,
                                @Autowired(required = false) BaselineLearningService baselineLearningService,
                                @Autowired TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.approvalService = approvalService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate : new Layer2PromptTemplate(eventEnricher, tieredStrategyProperties);
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
        return ThreatAssessment.builder()
                .riskScore(expertDecision.getRiskScore())
                .confidence(expertDecision.getConfidence())
                .indicators(new ArrayList<>())  // v5.1.0: 빈 리스트 (필드 삭제됨)
                .recommendedActions(List.of(mapActionToRecommendation(expertDecision.getAction())))
                .strategyName("Layer2-Expert")
                .assessedAt(LocalDateTime.now())
                .shouldEscalate(false)  // Layer2는 최종 계층
                .action(action)  // AI Native: LLM action 직접 저장
                .build();
    }

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

            // AI Native v5.0.0: Layer1 컨텍스트 수집 (동일 원본 데이터)
            // Layer2도 원본 데이터를 직접 분석하여 독립적인 검증 수행
            SessionContext sessionContext = buildSessionContext(event);
            BehaviorAnalysis behaviorAnalysis = analyzeBehaviorPatterns(event);
            List<Document> relatedDocuments = searchRelatedContext(event);

            // Layer2 전용 컨텍스트 수집
            // v5.1.0: gatherThreatIntelligence() 제거 - 익명 공격자 탐지용 (플랫폼 역할 아님)
            HistoricalContext historicalContext = analyzeHistoricalContext(event);

            // Layer1 결과 추출 (참고용)
            SecurityDecision layer1Decision = extractLayer1Decision(event);

            // AI Native v5.1.0: 변환 메서드 사용 (threatIntel 제거)
            Layer2PromptTemplate.SessionContext sessionCtx = convertToTemplateSessionContext(sessionContext);
            Layer2PromptTemplate.BehaviorAnalysis behaviorCtx = convertToTemplateBehaviorAnalysis(behaviorAnalysis);
            Layer2PromptTemplate.HistoricalContext historicalCtx = convertToTemplateHistoricalContext(historicalContext);

            // AI Native v5.1.0: 프롬프트 구성 (threatIntel, layer2Decision 파라미터 제거)
            String promptText = promptTemplate.buildPrompt(
                event,
                sessionCtx,           // Layer1 컨텍스트
                behaviorCtx,          // Layer1 컨텍스트
                relatedDocuments,     // Layer1 컨텍스트
                historicalCtx,        // Layer2 전용
                layer1Decision        // 참고용
            );

            Layer2SecurityResponse response = null;
            if (llmOrchestrator != null) {
                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(promptText))
                        .tier(2)
                        .preferredModel(modelName)
                        .securityTaskType(ExecutionContext.SecurityTaskType.EXPERT_INVESTIGATION)
                        .timeoutMs((int)timeoutMs)
                        .requestId(event.getEventId())
                        .build();

                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(timeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.warn("[Layer2][AI Native] LLM execution failed, applying failsafe blocking: {}", event.getEventId(), e);
                            // AI Native: 에러 복구 시 classification null - 플랫폼이 분류하지 않음
                            return Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"BLOCK\",\"classification\":null,\"scenario\":\"LLM execution failed - failsafe blocking applied\"}");
                        })
                        .block();

                response = parseJsonResponse(jsonResponse);
            } else {
                log.warn("UnifiedLLMOrchestrator not available for Layer 2 analysis");
                response = createDefaultResponse();
            }

            SecurityDecision expertDecision = convertToSecurityDecision(response, event, layer2Decision);

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
            String sourceIp = event.getSourceIp() != null ? event.getSourceIp() : "unknown";
            String userId = event.getUserId() != null ? event.getUserId() : "unknown";

            String incidentQuery = String.format("security incident from IP:%s user:%s",
                    sourceIp, userId);

            // AI Native v4.2.0: sourceIp → userId 수정 (findSimilarBehaviors 첫번째 파라미터는 userId)
            List<Document> similarIncidents = behaviorVectorService.findSimilarBehaviors(
                    userId,
                    incidentQuery,
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

        // AI Native: eventType 제거 - 사용자 ID 기반 검색
        String userId = event.getUserId() != null ? event.getUserId() : "unknown";
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
     */
    private SessionContext buildSessionContext(SecurityEvent event) {
        String sessionId = event.getSessionId();

        // PRIMARY SOURCE: SecurityEvent
        SessionContext context = new SessionContext();
        context.setSessionId(sessionId);
        context.setUserId(event.getUserId());
        context.setIpAddress(event.getSourceIp());
        context.setStartTime(LocalDateTime.now());

        // authMethod 및 recentRequestCount 추출 (metadata)
        if (event.getMetadata() != null) {
            Object authMethodObj = event.getMetadata().get("authMethod");
            if (authMethodObj != null) {
                context.setAuthMethod(authMethodObj.toString());
            }

            Object recentRequestCountObj = event.getMetadata().get("recentRequestCount");
            if (recentRequestCountObj instanceof Number) {
                context.setAccessFrequency(((Number) recentRequestCountObj).intValue());
            }
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
     * AI Native v5.0.0: 행동 패턴 분석 (Layer1과 동일 패턴)
     * Layer2도 원본 데이터를 직접 분석하여 독립적인 검증 수행
     */
    private BehaviorAnalysis analyzeBehaviorPatterns(SecurityEvent event) {
        BehaviorAnalysis analysis = new BehaviorAnalysis();
        String userId = event.getUserId();

        // 유사 이벤트 조회 (유지 - raw 데이터)
        List<String> similarEvents = findSimilarEventsForBehavior(event);
        analysis.setSimilarEvents(similarEvents);

        // Zero Trust: 서비스 상태를 명시적으로 LLM에게 전달
        if (baselineLearningService == null) {
            analysis.setBaselineContext("[SERVICE_UNAVAILABLE] Baseline learning service not configured");
            analysis.setBaselineEstablished(false);
        } else if (userId == null) {
            log.error("[Layer2][SYSTEM_ERROR] userId is null - authentication system failure");
            analysis.setBaselineContext("[SYSTEM_ERROR] Authentication failure - userId unavailable");
            analysis.setBaselineEstablished(false);
        } else {
            try {
                String baselineContext = baselineLearningService.buildBaselinePromptContext(userId, event);

                if (baselineContext == null || baselineContext.isEmpty()) {
                    analysis.setBaselineContext("[NO_DATA] Baseline service returned empty response");
                } else {
                    analysis.setBaselineContext(baselineContext);
                    log.debug("[Layer2] Baseline context generated for user {}", userId);
                }

                analysis.setBaselineEstablished(baselineLearningService.getBaseline(userId) != null);

            } catch (Exception e) {
                log.warn("[Layer2] Baseline service error for user {}: {}", userId, e.getMessage());
                analysis.setBaselineContext("[SERVICE_ERROR] Baseline service error: " + e.getMessage());
                analysis.setBaselineEstablished(false);
            }
        }

        return analysis;
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

        String description = event.getDescription();
        if (description == null || description.isEmpty()) {
            log.debug("[Layer2][AI Native] No description for similar events search, skipping");
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
            log.warn("[Layer2] Similar events search failed", e);
            return Collections.emptyList();
        }
    }

    /**
     * AI Native v5.0.0: 벡터 스토어에서 관련 문서 검색 (Layer1과 동일 패턴)
     * Layer2도 원본 RAG 데이터를 직접 검색하여 독립적인 분석 수행
     */
    private List<Document> searchRelatedContext(SecurityEvent event) {
        if (unifiedVectorService == null) {
            return Collections.emptyList();
        }

        try {
            String httpMethod = eventEnricher.getHttpMethod(event).orElse(null);

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

            // 3. HTTP 메서드
            if (httpMethod != null && !"unknown".equalsIgnoreCase(httpMethod)) {
                queryBuilder.append(httpMethod).append(" ");
            }

            // 4. 사용자 ID
            if (event.getUserId() != null && !event.getUserId().equals("unknown")) {
                queryBuilder.append("user:").append(event.getUserId()).append(" ");
            }

            // 5. 소스 IP
            if (event.getSourceIp() != null) {
                queryBuilder.append("IP:").append(event.getSourceIp()).append(" ");
            }

            String query = queryBuilder.toString().trim();
            if (query.isEmpty()) {
                log.debug("[Layer2][AI Native] Empty query, skipping vector search for event {}",
                    event.getEventId());
                return Collections.emptyList();
            }

            double similarityThreshold = tieredStrategyProperties.getLayer2().getRag().getSimilarityThreshold();

            String documentTypeFilter = String.format("documentType == '%s'",
                VectorDocumentType.BEHAVIOR.getValue());

            org.springframework.ai.vectorstore.SearchRequest searchRequest =
                org.springframework.ai.vectorstore.SearchRequest.builder()
                    .query(query)
                    .topK(ragTopK)
                    .similarityThreshold(similarityThreshold)
                    .filterExpression(documentTypeFilter)
                    .build();

            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);

            log.debug("[Layer2] RAG behavioral context search: {} documents found for event {}",
                documents != null ? documents.size() : 0, event.getEventId());

            return documents != null ? documents : Collections.emptyList();

        } catch (Exception e) {
            log.debug("[Layer2] Vector store context search failed", e);
            return Collections.emptyList();
        }
    }

    /**
     * AI Native v5.0.0: SessionContext를 Layer2PromptTemplate.SessionContext로 변환
     */
    private Layer2PromptTemplate.SessionContext convertToTemplateSessionContext(SessionContext sessionContext) {
        Layer2PromptTemplate.SessionContext ctx = new Layer2PromptTemplate.SessionContext();
        ctx.setSessionId(sessionContext.getSessionId());
        ctx.setUserId(sessionContext.getUserId());
        ctx.setAuthMethod(sessionContext.getAuthMethod());
        ctx.setRecentActions(sessionContext.getRecentActions());
        return ctx;
    }

    /**
     * AI Native v5.0.0: BehaviorAnalysis를 Layer2PromptTemplate.BehaviorAnalysis로 변환
     */
    private Layer2PromptTemplate.BehaviorAnalysis convertToTemplateBehaviorAnalysis(BehaviorAnalysis behaviorAnalysis) {
        Layer2PromptTemplate.BehaviorAnalysis ctx = new Layer2PromptTemplate.BehaviorAnalysis();
        ctx.setSimilarEvents(behaviorAnalysis.getSimilarEvents());
        ctx.setBaselineContext(behaviorAnalysis.getBaselineContext());
        ctx.setBaselineEstablished(behaviorAnalysis.isBaselineEstablished());
        return ctx;
    }

    // v5.1.0: convertToTemplateThreatIntel() 메서드 삭제
    // - ThreatIntelligence 관련 코드 전체 제거로 인해 불필요
    // - 플랫폼 핵심: "인증된 사용자가 진짜인가?" 검증

    /**
     * AI Native v5.0.0: HistoricalContext를 Layer2PromptTemplate.HistoricalContext로 변환
     * List<String> -> List<String> 타입 유지 (프롬프트 템플릿에서 직접 처리)
     *
     * AI Native v5.1.0: previousChallenges 필드 추가 (userId 기반)
     */
    private Layer2PromptTemplate.HistoricalContext convertToTemplateHistoricalContext(HistoricalContext historicalContext) {
        Layer2PromptTemplate.HistoricalContext ctx = new Layer2PromptTemplate.HistoricalContext();
        ctx.setSimilarIncidents(historicalContext.getSimilarIncidents());
        ctx.setPreviousAttacks(historicalContext.getPreviousAttacks());
        ctx.setPreviousChallenges(historicalContext.getPreviousChallenges());
        return ctx;
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
     * AI Native v5.1.0: 응답 검증 (삭제된 필드 참조 제거)
     * Layer2SecurityResponse에는 6개 필드만 존재:
     * riskScore, confidence, action, reasoning, mitre, recommendation
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

        // v5.1.0: tactics, techniques, iocIndicators 검증 코드 삭제
        // - Layer2SecurityResponse에서 해당 필드들 제거됨
        // - LLM 응답에서 해당 필드 요청하지 않음

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
     * AI Native v5.1.0: Layer2SecurityResponse를 SecurityDecision으로 변환
     * 삭제된 필드 참조 제거 (scenario, businessImpact, expertRecommendation, 등)
     * Layer2SecurityResponse 필드: riskScore, confidence, action, reasoning, mitre, recommendation
     */
    private SecurityDecision convertToSecurityDecision(Layer2SecurityResponse response,
                                                       SecurityEvent event,
                                                       SecurityDecision layer2Decision) {
        // Null safety: response가 null인 경우 기본 응답 생성
        if (response == null) {
            response = createDefaultResponse();
        }

        SecurityDecision.Action action = mapStringToAction(response.getAction());

        // AI Native v5.1.0: LLM 응답 그대로 사용
        // 삭제된 필드: scenario, businessImpact, expertRecommendation, requiresApproval, playbookId
        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
                .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                .reasoning(response.getReasoning())
                .expertRecommendation(response.getRecommendation())  // recommendation -> expertRecommendation
                .eventId(event != null ? event.getEventId() : "unknown")
                .analysisTime(System.currentTimeMillis())
                .processingLayer(2)
                .llmModel(modelName)
                .build();

        // AI Native v5.1.0: MITRE 매핑 (mitre 필드 사용)
        if (response.getMitre() != null && !response.getMitre().isEmpty()) {
            Map<String, String> mitreMapping = new HashMap<>();
            mitreMapping.put(response.getMitre(), response.getMitre());
            decision.setMitreMapping(mitreMapping);
        }

        // v5.1.0: tactics, iocIndicators 관련 코드 삭제 (필드 제거됨)

        return decision;
    }

    /**
     * AI Native v5.1.0: LLM JSON 응답 파싱 (간소화)
     * Layer2SecurityResponse 필드: riskScore, confidence, action, reasoning, mitre, recommendation
     * 삭제된 필드 파싱 코드 제거 (classification, scenario, tactics, techniques 등)
     */
    private Layer2SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            String cleanedJson = extractJsonObject(jsonResponse);
            JsonNode jsonNode = objectMapper.readTree(cleanedJson);

            // AI Native v5.0.0: 풀네임 우선 (riskScore, confidence, action, reasoning)
            // 하위호환을 위해 약어(r,c,a,d)도 지원
            Double riskScore = (jsonNode.has("riskScore") && !jsonNode.get("riskScore").isNull()) ? jsonNode.get("riskScore").asDouble()
                : ((jsonNode.has("r") && !jsonNode.get("r").isNull()) ? jsonNode.get("r").asDouble() : Double.NaN);
            Double confidence = (jsonNode.has("confidence") && !jsonNode.get("confidence").isNull()) ? jsonNode.get("confidence").asDouble()
                : ((jsonNode.has("c") && !jsonNode.get("c").isNull()) ? jsonNode.get("c").asDouble() : Double.NaN);
            String action = (jsonNode.has("action") && !jsonNode.get("action").isNull()) ? jsonNode.get("action").asText()
                : ((jsonNode.has("a") && !jsonNode.get("a").isNull()) ? expandAction(jsonNode.get("a").asText()) : "ESCALATE");
            String reasoning = (jsonNode.has("reasoning") && !jsonNode.get("reasoning").isNull()) ? jsonNode.get("reasoning").asText()
                : ((jsonNode.has("d") && !jsonNode.get("d").isNull()) ? jsonNode.get("d").asText() : "No reasoning");

            // AI Native v5.0.0: MITRE ATT&CK 필드 파싱 (mitre 우선, m 하위호환)
            String mitre = (jsonNode.has("mitre") && !jsonNode.get("mitre").isNull())
                ? jsonNode.get("mitre").asText()
                : ((jsonNode.has("m") && !jsonNode.get("m").isNull()) ? jsonNode.get("m").asText() : null);

            // AI Native v5.0.0: recommendation 필드 파싱 (recommendation 우선, rec 하위호환)
            String recommendation = (jsonNode.has("recommendation") && !jsonNode.get("recommendation").isNull())
                ? jsonNode.get("recommendation").asText()
                : ((jsonNode.has("rec") && !jsonNode.get("rec").isNull()) ? jsonNode.get("rec").asText() : null);

            // v5.1.0: 삭제된 필드 파싱 코드 제거
            // - classification, scenario, threatActor, expertRecommendation: 프롬프트에서 요청 안함
            // - tactics, techniques, iocIndicators: 배열 필드 제거됨
            // - createIncident: 미사용

            Layer2SecurityResponse response = Layer2SecurityResponse.builder()
                    .riskScore(riskScore)
                    .confidence(confidence)
                    .action(action)
                    .reasoning(reasoning)
                    .mitre(mitre)
                    .recommendation(recommendation)
                    .build();

            return validateAndFixResponse(response);

        } catch (Exception e) {
            log.error("Failed to parse JSON response from Layer2 LLM: {}", jsonResponse, e);
            return createDefaultResponse();
        }
    }

    /**
     * AI Native v5.1.0: 기본 응답 생성 (간소화)
     * Layer2SecurityResponse 필드: riskScore, confidence, action, reasoning, mitre, recommendation
     */
    private Layer2SecurityResponse createDefaultResponse() {
        return Layer2SecurityResponse.builder()
                .riskScore(Double.NaN)  // AI Native: LLM 분석 미수행
                .confidence(Double.NaN)  // AI Native: LLM 분석 미수행
                .action("ESCALATE")
                .reasoning("Layer 2 LLM analysis unavailable")
                .mitre(null)
                .recommendation(null)
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

    /**
     * AI Native v5.0.0: 세션 컨텍스트 (Layer1과 동일 구조)
     * Layer2도 원본 데이터를 직접 분석하여 독립적인 검증 수행
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

        public List<String> getRecentActions() { return recentActions; }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        public int getAccessFrequency() { return accessFrequency; }
        public void setAccessFrequency(int accessFrequency) { this.accessFrequency = accessFrequency; }
    }

    /**
     * AI Native v5.0.0: 행동 분석 (Layer1과 동일 구조)
     * Layer2도 원본 데이터를 직접 분석하여 독립적인 검증 수행
     */
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
     * AI Native v5.1.0: 벡터 데이터베이스에 저장 (간소화)
     * Layer2SecurityResponse 필드: riskScore, confidence, action, reasoning, mitre, recommendation
     */
    private void storeInVectorDatabase(SecurityEvent event, SecurityDecision decision, Layer2SecurityResponse response) {
        if (unifiedVectorService == null) return;

        try {
            // v5.1.0: 삭제된 필드 참조 제거 (classification, tactics 등)
            String content = String.format(
                    "User: %s, Risk: %.2f, Action: %s, MITRE: %s, Reasoning: %s",
                    event.getUserId() != null ? event.getUserId() : "unknown",
                    decision.getRiskScore(),
                    decision.getAction(),
                    response.getMitre() != null ? response.getMitre() : "",
                    decision.getReasoning()
            );

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

            // SecurityDecision 정보
            double metaRiskScore = decision.getRiskScore();
            double metaConfidence = decision.getConfidence();
            if (!Double.isNaN(metaRiskScore)) {
                metadata.put("riskScore", metaRiskScore);
            }
            metadata.put("action", decision.getAction() != null ? decision.getAction().toString() : "ESCALATE");
            if (!Double.isNaN(metaConfidence)) {
                metadata.put("confidence", metaConfidence);
            }
            if (decision.getThreatCategory() != null) {
                metadata.put("threatCategory", decision.getThreatCategory());
            }

            // v5.1.0: MITRE 정보 (mitre 필드 사용)
            if (response.getMitre() != null && !response.getMitre().isEmpty()) {
                metadata.put("mitreTactic", response.getMitre());
            }

            Document document = new Document(content, metadata);
            unifiedVectorService.storeDocument(document);

            // v3.1.0: MITIGATE -> BLOCK으로 통합됨
            SecurityDecision.Action storeAction = decision.getAction();
            if (storeAction == SecurityDecision.Action.BLOCK) {
                storeThreatDocument(event, decision, response, content);
            }

        } catch (Exception e) {
            log.debug("Failed to store in vector database", e);
        }
    }

    /**
     * AI Native v5.1.0: 위협 문서 저장 (간소화)
     * Layer2SecurityResponse 필드: riskScore, confidence, action, reasoning, mitre, recommendation
     */
    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, Layer2SecurityResponse response, String analysisContent) {
        try {
            Map<String, Object> threatMetadata = new HashMap<>();

            // 위협 전용 documentType
            threatMetadata.put("documentType", VectorDocumentType.THREAT.getValue());
            double riskScore = decision.getRiskScore();
            if (!Double.isNaN(riskScore)) {
                threatMetadata.put("riskScore", riskScore);
            }

            // 기본 정보
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

            // v5.1.0: MITRE 정보 (mitre 필드 사용)
            if (response.getMitre() != null && !response.getMitre().isEmpty()) {
                threatMetadata.put("mitreTactic", response.getMitre());
            }

            // LLM 결정 정보
            double confidence = decision.getConfidence();
            if (!Double.isNaN(confidence)) {
                threatMetadata.put("confidence", confidence);
            }
            threatMetadata.put("action", decision.getAction().toString());

            // v5.1.0: 위협 설명 (간소화)
            String threatDescription = String.format(
                "Layer2 Expert Threat: User=%s, IP=%s, Risk=%.2f, MITRE=%s, Action=%s, Reasoning=%s",
                event.getUserId() != null ? event.getUserId() : "unknown",
                event.getSourceIp() != null ? event.getSourceIp() : "unknown",
                decision.getRiskScore(),
                response.getMitre() != null ? response.getMitre() : "",
                decision.getAction(),
                decision.getReasoning() != null ? decision.getReasoning().substring(0, Math.min(150, decision.getReasoning().length())) : ""
            );

            Document threatDoc = new Document(threatDescription, threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

            log.info("[Layer2] 위협 패턴 저장 완료: userId={}, riskScore={}, mitre={}",
                event.getUserId(), decision.getRiskScore(), response.getMitre());

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