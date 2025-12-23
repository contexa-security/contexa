package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.response.Layer2SecurityResponse;
import io.contexa.contexacore.autonomous.tiered.template.Layer2PromptTemplate;
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
import java.util.concurrent.TimeUnit;
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
    private final BehaviorVectorService behaviorVectorService;
    private final UnifiedVectorService unifiedVectorService;
    private final BaselineLearningService baselineLearningService;
    private final TieredStrategyProperties tieredStrategyProperties;
    private final Cache<String, SessionContext> sessionContextCache;
    private final ObjectMapper objectMapper = new ObjectMapper();


    @Value("${spring.ai.security.layer2.model:llama3.1:8b}")
    private String modelName;

    @Value("${spring.ai.security.tiered.layer2.timeout-ms:10000}")
    private long timeoutMs;

    @Value("${spring.ai.security.tiered.layer2.vector-search-limit:10}")
    private int vectorSearchLimit;

    @Autowired
    public Layer2ContextualStrategy(@Autowired(required = false) UnifiedLLMOrchestrator llmOrchestrator,
                                    @Autowired(required = false) UnifiedVectorService unifiedVectorService,
                                    @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                                    @Autowired(required = false) SecurityEventEnricher eventEnricher,
                                    @Autowired(required = false) Layer2PromptTemplate promptTemplate,
                                    @Autowired(required = false) BehaviorVectorService behaviorVectorService,
                                    @Autowired(required = false) BaselineLearningService baselineLearningService,
                                    @Autowired TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.unifiedVectorService = unifiedVectorService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate : new Layer2PromptTemplate(eventEnricher, tieredStrategyProperties);
        this.behaviorVectorService = behaviorVectorService;
        this.baselineLearningService = baselineLearningService;
        this.tieredStrategyProperties = tieredStrategyProperties;

        // Phase 2-5: 메모리 누수 수정 - Caffeine TTL 캐시로 교체
        TieredStrategyProperties.Layer2.Cache cacheConfig = tieredStrategyProperties.getLayer2().getCache();
        this.sessionContextCache = Caffeine.newBuilder()
                .maximumSize(cacheConfig.getMaxSize())
                .expireAfterAccess(cacheConfig.getTtlMinutes(), TimeUnit.MINUTES)
                .recordStats()
                .build();

        log.info("Layer 2 Contextual Strategy initialized with UnifiedLLMOrchestrator");
        log.info("  - Model: {}", modelName);
        log.info("  - Timeout: {}ms", timeoutMs);
        log.info("  - UnifiedVectorService available: {}", unifiedVectorService != null);
        log.info("  - BaselineLearningService available: {}", baselineLearningService != null);
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.info("Layer 2 Contextual Strategy evaluating event: {}", event.getEventId());
        SecurityDecision layer1Decision = createDefaultDecision();
        SecurityDecision decision = analyzeWithContext(event, layer1Decision);
        boolean shouldEscalate = decision.getAction() == SecurityDecision.Action.ESCALATE;
        String action = decision.getAction() != null ? decision.getAction().name() : "ESCALATE";
        return ThreatAssessment.builder()
                .riskScore(decision.getRiskScore())
                .confidence(decision.getConfidence())
                .indicators(new ArrayList<>())
                .recommendedActions(List.of(mapActionToRecommendation(decision.getAction())))
                .strategyName("Layer2-Contextual")
                .shouldEscalate(shouldEscalate)
                .action(action)  // AI Native: LLM action 직접 저장
                .build();
    }

    public SecurityDecision analyzeWithContext(SecurityEvent event, SecurityDecision layer1Decision) {
        long startTime = System.currentTimeMillis();

        try {
            // 1. 세션 컨텍스트 수집
            SessionContext sessionContext = buildSessionContext(event);

            // 3. 행동 패턴 분석 (Phase 8: sessionContext 파라미터 제거 - 미사용)
            BehaviorAnalysis behaviorAnalysis = analyzeBehaviorPatterns(event);

            // 4. 벡터 스토어에서 관련 컨텍스트 검색
            List<Document> relatedDocuments = searchRelatedContext(event);

            // 4. PromptTemplate을 통한 프롬프트 구성
            Layer2PromptTemplate.SessionContext sessionCtx = convertToTemplateSessionContext(sessionContext);
            Layer2PromptTemplate.BehaviorAnalysis behaviorCtx = convertToTemplateBehaviorAnalysis(behaviorAnalysis);

            String promptText = promptTemplate.buildPrompt(event, layer1Decision, sessionCtx, behaviorCtx, relatedDocuments);

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

        // 캐시 확인 (Caffeine: getIfPresent 사용)
        if (sessionId != null) {
            SessionContext cached = sessionContextCache.getIfPresent(sessionId);
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
                        .range(ZeroTrustRedisKeys.sessionActions(sessionId), -10, -1);
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

    private BehaviorAnalysis analyzeBehaviorPatterns(SecurityEvent event) {
        BehaviorAnalysis analysis = new BehaviorAnalysis();
        String userId = event.getUserId();

        // 유사 이벤트 조회 (유지 - raw 데이터)
        // AI Native: 빈 리스트는 그대로 유지, 마커 생성 금지
        List<String> similarEvents = findSimilarEvents(event);
        analysis.setSimilarEvents(similarEvents);

        if (baselineLearningService != null && userId != null) {
            analysis.setBaselineContext(baselineLearningService.buildBaselinePromptContext(userId, event));
            analysis.setBaselineEstablished(baselineLearningService.getBaseline(userId) != null);
            log.debug("[Layer2] Baseline context generated for user {}", userId);
        } else {
            analysis.setBaselineContext(null);
            analysis.setBaselineEstablished(false);
        }

        return analysis;
    }

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
        if (redisTemplate == null) {
            return similar;
        }

        String pattern = "event:similar:" + event.getEventType() + ":*";
        int limit = 5;

        try {
            // Redis SCAN: 점진적 스캔으로 블로킹 방지
            ScanOptions scanOptions = ScanOptions.scanOptions()
                    .match(pattern)
                    .count(100)  // 배치 크기 (한 번에 스캔할 키 수)
                    .build();

            try (Cursor<String> cursor = redisTemplate.scan(scanOptions)) {
                while (cursor.hasNext() && similar.size() < limit) {
                    String key = cursor.next();
                    String eventId = key.substring(key.lastIndexOf(":") + 1);
                    similar.add(eventId);
                }
            }
        } catch (Exception e) {
            log.debug("[Layer2] Failed to find similar events via SCAN", e);
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

            // AI Native: getThreatType() deprecated 필드 사용 제거
            // 위협 타입은 ThreatAssessment에서 LLM이 결정

            String query = queryBuilder.toString().trim();

            // 설정에서 유사도 임계값 가져오기
            double similarityThreshold = tieredStrategyProperties.getLayer2().getRag().getSimilarityThreshold();
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(Math.min(15, vectorSearchLimit * 2))
                    .similarityThreshold(similarityThreshold)
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

    private Layer2PromptTemplate.BehaviorAnalysis convertToTemplateBehaviorAnalysis(BehaviorAnalysis behaviorAnalysis) {
        Layer2PromptTemplate.BehaviorAnalysis ctx = new Layer2PromptTemplate.BehaviorAnalysis();

        ctx.setSimilarEvents(behaviorAnalysis.getSimilarEvents());
        ctx.setBaselineContext(behaviorAnalysis.getBaselineContext());
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

    private Layer2SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            // JSON 문자열에서 {}만 추출
            String cleanedJson = extractJsonObject(jsonResponse);

            // 1단계: 축약 JSON 파싱 우선 시도 (프롬프트 최적화 후 표준 형식)
            Layer2SecurityResponse compactResponse = Layer2SecurityResponse.fromCompactJson(cleanedJson);
            if (isValidResponse(compactResponse)) {
                log.debug("Layer2 compact JSON parsing successful: {}", cleanedJson);
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

            log.debug("Layer2 compact parsing failed, falling back to Jackson: {}", cleanedJson);
            JsonNode jsonNode = objectMapper.readTree(cleanedJson);
            Double riskScore = jsonNode.has("riskScore") && !jsonNode.get("riskScore").isNull()
                    ? jsonNode.get("riskScore").asDouble() : null;
            Double confidence = jsonNode.has("confidence") && !jsonNode.get("confidence").isNull()
                    ? jsonNode.get("confidence").asDouble() : null;
            String action = jsonNode.has("action") ? jsonNode.get("action").asText() : "ESCALATE";
            String reasoning = jsonNode.has("reasoning") ? jsonNode.get("reasoning").asText() : "No reasoning provided";
            // AI Native: threatCategory는 LLM이 분류, 없으면 null 유지
            // 플랫폼이 기본값이나 마커를 생성하지 않음
            String threatCategory = jsonNode.has("threatCategory") && !jsonNode.get("threatCategory").asText().isBlank()
                    ? jsonNode.get("threatCategory").asText() : null;

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
     * Response 객체 유효성 검사
     * riskScore 또는 confidence가 설정되어 있으면 유효한 응답으로 판단
     */
    private boolean isValidResponse(Layer2SecurityResponse response) {
        if (response == null) return false;
        return response.getRiskScore() != null || response.getConfidence() != null;
    }

    private Layer2SecurityResponse createDefaultResponse() {
        return Layer2SecurityResponse.builder()
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .action("ESCALATE")  // AI Native: 분석 불가 시 상위 Layer로 에스컬레이션
                .reasoning("Layer 2 LLM analysis unavailable - escalating to Layer 3")
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
     * Layer 1 결정 향상
     */
    private SecurityDecision enhanceLayer1Decision(SecurityDecision layer1Decision, long startTime) {
        // AI Native: Layer1 신뢰도를 그대로 사용 (플랫폼이 LLM 결정 가공 금지)
        SecurityDecision enhanced = SecurityDecision.builder()
                .action(layer1Decision.getAction())
                .riskScore(layer1Decision.getRiskScore())
                .confidence(layer1Decision.getConfidence())
                .analysisTime(startTime)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .processingLayer(2)
                .eventId(layer1Decision.getEventId())
                .reasoning("[AI Native] Layer 2 analysis failed, using Layer 1 decision unchanged")
                .build();

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
            redisTemplate.opsForList().rightPush(
                    ZeroTrustRedisKeys.sessionActions(sessionId),
                    String.format("%s:%s:%s", event.getEventType(),
                            eventEnricher.getTargetResource(event).orElse("unknown"),
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
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            // AI Native: null인 경우 필드 생략 (LLM이 "unknown"을 실제 값으로 오해 방지)
            if (event.getEventId() != null) {
                metadata.put("eventId", event.getEventId());
            }
            if (event.getUserId() != null) {
                metadata.put("userId", event.getUserId());
            }

            // SecurityEvent 정보
            if (event.getEventType() != null) {
                metadata.put("eventType", event.getEventType().toString());
            }
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
            // AI Native: null인 경우 필드 생략
            if (event.getEventId() != null) {
                threatMetadata.put("eventId", event.getEventId());
            }
            threatMetadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            if (event.getUserId() != null) {
                threatMetadata.put("userId", event.getUserId());
            }
            if (event.getEventType() != null) {
                threatMetadata.put("eventType", event.getEventType().toString());
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

            log.info("[Layer2] 위협 패턴 저장 완료: userId={}, riskScore={}, threatCategory={}, behaviorPatterns={}",
                event.getUserId(), decision.getRiskScore(), decision.getThreatCategory(),
                decision.getBehaviorPatterns() != null ? decision.getBehaviorPatterns().size() : 0);

        } catch (Exception e) {
            log.warn("[Layer2] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }
    @Override
    protected String getLayerName() {
        return "Layer2";
    }

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
    public List<String> getRecommendedActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        actions.add("MONITOR_USER_BEHAVIOR");
        actions.add("ANALYZE_SESSION_CONTEXT");
        return actions;
    }

    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        log.warn("[Layer2][AI Native] calculateRiskScore called without LLM analysis - returning NaN");
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
            int maxRecentActions = tieredStrategyProperties.getLayer2().getSession().getMaxRecentActions();
            if (recentActions.size() > maxRecentActions) {
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
            return "AccessFrequency: " + accessFrequency;
        }

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
    }

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

        // AI Native: threatCategory가 null이면 null 유지 (플랫폼 분류 금지)
        // 마커 생성도 AI Native 위반이므로 null 그대로 유지

        // mitigationActions 검증
        if (response.getMitigationActions() == null) {
            response.setMitigationActions(new ArrayList<>());
        }

        return response;
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