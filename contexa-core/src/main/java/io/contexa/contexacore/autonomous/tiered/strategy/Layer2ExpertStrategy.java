package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
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

    @Value("${spring.ai.security.tiered.layer2.timeout-ms:30000}")
    private long timeoutMs;

    @Value("${spring.ai.security.tiered.layer2.enable-soar:false}")
    private boolean enableSoar;

    @Value("${spring.ai.security.tiered.layer2.rag.top-k:10}")
    private int ragTopK;

    @Autowired
    public Layer2ExpertStrategy(UnifiedLLMOrchestrator llmOrchestrator,
                                ApprovalService approvalService,
                                RedisTemplate<String, Object> redisTemplate,
                                SecurityEventEnricher eventEnricher,
                                SecurityPromptTemplate promptTemplate,
                                UnifiedVectorService unifiedVectorService,
                                BehaviorVectorService behaviorVectorService,
                                BaselineLearningService baselineLearningService,
                                TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.approvalService = approvalService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate : new SecurityPromptTemplate(eventEnricher, tieredStrategyProperties, baselineLearningService);
        this.behaviorVectorService = behaviorVectorService;
        this.unifiedVectorService = unifiedVectorService;
        this.baselineLearningService = baselineLearningService;
        this.tieredStrategyProperties = tieredStrategyProperties;}

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.warn("Layer 2 Expert Strategy evaluating event: {}", event.getEventId());

        SecurityDecision layer2Decision = extractLayer2Decision(event);
        SecurityDecision expertDecision = performDeepAnalysis(event, layer2Decision);
        String action = expertDecision.getAction() != null ? expertDecision.getAction().name() : "ESCALATE";

        return ThreatAssessment.builder()
                .riskScore(expertDecision.getRiskScore())
                .confidence(expertDecision.getConfidence())
                .indicators(new ArrayList<>())  
                .recommendedActions(List.of(mapActionToRecommendation(expertDecision.getAction())))
                .strategyName("Layer2-Expert")
                .assessedAt(LocalDateTime.now())
                .shouldEscalate(false)  
                .action(action)  
                .reasoning(expertDecision.getReasoning())  
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

            SecurityPromptTemplate.SessionContext sessionCtx = getCachedOrBuildSessionContext(event);
            SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = getCachedOrBuildBehaviorAnalysis(event);
            List<Document> relatedDocuments = getCachedOrSearchRelatedContext(event);

            String promptText = promptTemplate.buildPrompt(event, sessionCtx, behaviorCtx, relatedDocuments);

            SecurityResponse response = null;
            if (llmOrchestrator != null) {
                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(promptText))
                        .tier(2)
                        .securityTaskType(ExecutionContext.SecurityTaskType.EXPERT_INVESTIGATION)
                        .timeoutMs((int)timeoutMs)
                        .requestId(event.getEventId())
                        .temperature(0.0)
                        .topP(1.0)
                        .build();

                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(timeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.warn("[Layer2][AI Native] LLM execution failed, applying failsafe blocking: {}", event.getEventId(), e);
                            
                            return Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"BLOCK\",\"reasoning\":\"LLM execution failed - failsafe blocking applied\"}");
                        })
                        .block();

                response = parseJsonResponse(jsonResponse);
            } else {
                log.warn("UnifiedLLMOrchestrator not available for Layer 2 analysis");
                response = createDefaultResponse();
            }

            SecurityDecision expertDecision = convertToSecurityDecision(response, event);

            if (enableSoar && expertDecision.getAction() == SecurityDecision.Action.BLOCK) {
                executeSoarPlaybook(expertDecision, event);
            }

            if (expertDecision.isRequiresApproval() && approvalService != null) {
                handleApprovalProcess(expertDecision, event);
            }

            if (expertDecision.getAction() == SecurityDecision.Action.BLOCK) {
                createSecurityIncident(expertDecision, event);
            }

            storeInVectorDatabase(event, expertDecision, response);

            SecurityDecision.Action expertAction = expertDecision.getAction();
            if (expertAction == SecurityDecision.Action.BLOCK) {
                String sourceIp = event.getSourceIp();
                if (sourceIp != null && !sourceIp.isEmpty()) {
                    
                    incrementAttackCount(sourceIp);
                }
            }

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

    public Mono<SecurityDecision> performDeepAnalysisAsync(SecurityEvent event,
                                                                                  SecurityDecision layer2Decision) {
        return Mono.fromCallable(() -> performDeepAnalysis(event, layer2Decision))
                .timeout(Duration.ofMillis(timeoutMs))
                .onErrorResume(throwable -> {
                    log.error("Layer 2 async analysis failed or timed out", throwable);
                    return Mono.just(createFailsafeDecision(event, layer2Decision, System.currentTimeMillis()));
                });
    }

    private HistoricalContext analyzeHistoricalContext(SecurityEvent event) {
        HistoricalContext context = new HistoricalContext();

        if (event == null) {
            context.setSimilarIncidents(new ArrayList<>());
            context.setPreviousAttacks(0);
            
            return context;
        }

        List<String> similarIncidents = findSimilarIncidents(event);
        context.setSimilarIncidents(similarIncidents);

        String userId = event.getUserId();
        int previousBlocks = getPreviousBlocksForUser(userId);
        int previousChallenges = getPreviousChallengesForUser(userId);

        context.setPreviousAttacks(previousBlocks);
        context.setPreviousChallenges(previousChallenges);

        return context;
    }

    private List<String> findSimilarIncidents(SecurityEvent event) {
        if (behaviorVectorService == null) {
            return findSimilarIncidentsFallback(event);
        }

        try {

            StringBuilder incidentQuery = new StringBuilder("security incident");
            if (event.getSourceIp() != null) {
                incidentQuery.append(" from IP:").append(event.getSourceIp());
            }
            String userId = event.getUserId();
            if (userId != null) {
                incidentQuery.append(" user:").append(userId);
            }

            if (userId == null) {
                return findSimilarIncidentsFallback(event);
            }

            String sourceIp = event.getSourceIp();
            
            String requestPath = event.getMetadata() != null ?
                    (String) event.getMetadata().get("requestPath") : null;
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

        if (event == null) {
            return incidents;
        }

        if (redisTemplate == null) {
            return incidents;
        }

        String userId = event.getUserId();
        if (userId == null) {
            return incidents;
        }
        String pattern = "incident:*:" + userId;
        int limit = 5;

        try {
            
            ScanOptions scanOptions = ScanOptions.scanOptions()
                    .match(pattern)
                    .count(100)  
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
                    }

        return incidents;
    }

    private BaseSessionContext buildSessionContext(SecurityEvent event) {
        String sessionId = event.getSessionId();

        BaseSessionContext context = new BaseSessionContext();
        context.setSessionId(sessionId);
        context.setUserId(event.getUserId());
        context.setIpAddress(event.getSourceIp());
        context.setStartTime(LocalDateTime.now());

        if (event.getMetadata() != null) {
            Object recentRequestCountObj = event.getMetadata().get("recentRequestCount");
            if (recentRequestCountObj instanceof Number) {
                context.setAccessFrequency(((Number) recentRequestCountObj).intValue());
            }
        }

        if (event.getUserAgent() != null) {
            context.setUserAgent(event.getUserAgent());
        }

        if (sessionId != null && redisTemplate != null) {
            try {
                @SuppressWarnings("unchecked")
                List<String> recentActions = (List<String>) (List<?>) redisTemplate.opsForList()
                        .range(ZeroTrustRedisKeys.sessionActions(sessionId), -10, -1);
                if (recentActions != null && !recentActions.isEmpty()) {
                    context.setRecentActions(recentActions);
                }
            } catch (Exception e) {
                            }
        }

        return context;
    }

    private boolean detectSessionContextChange(SecurityEvent event, BaseSessionContext currentContext) {
        if (event == null || currentContext == null) {
            return false;
        }

        return isSessionContextChangedFromRedis(
            event.getSessionId(),
            currentContext.getIpAddress(),
            currentContext.getUserAgent(),
            redisTemplate
        );
    }

    @Override
    protected List<String> findSimilarEventsForLayer(SecurityEvent event) {
        return findSimilarEventsForBehavior(event);
    }

    private BaseBehaviorAnalysis analyzeBehaviorPatterns(SecurityEvent event) {
        return analyzeBehaviorPatternsBase(event, baselineLearningService);
    }

    private List<String> findSimilarEventsForBehavior(SecurityEvent event) {
        if (behaviorVectorService == null) {
            return Collections.emptyList();
        }

        String userId = event.getUserId();
        if (userId == null) {
            log.error("[Layer2][SYSTEM_ERROR] userId null in findSimilarEventsForBehavior");
            return Collections.emptyList();
        }

        final String currentIp = event.getSourceIp();
        
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

        } catch (Exception e) {
            log.warn("[Layer2] Similar events search failed", e);
            return Collections.emptyList();
        }
    }

    private List<Document> searchRelatedContext(SecurityEvent event) {
        double similarityThreshold = tieredStrategyProperties.getLayer2().getRag().getSimilarityThreshold();
        return searchRelatedContextBase(event, unifiedVectorService, eventEnricher, ragTopK, similarityThreshold);
    }

    private SecurityPromptTemplate.SessionContext getCachedOrBuildSessionContext(SecurityEvent event) {
        String eventId = event.getEventId();

        SecurityPromptTemplate.SessionContext cached = SESSION_CONTEXT_CACHE.getIfPresent(eventId);
        if (cached != null) {
                        return cached;
        }

                BaseSessionContext baseCtx = buildSessionContext(event);

        SecurityPromptTemplate.SessionContext ctx = new SecurityPromptTemplate.SessionContext();
        ctx.setSessionId(baseCtx.getSessionId());
        ctx.setUserId(baseCtx.getUserId());
        ctx.setAuthMethod(baseCtx.getAuthMethod());
        ctx.setRecentActions(baseCtx.getRecentActions());

        return ctx;
    }

    private SecurityPromptTemplate.BehaviorAnalysis getCachedOrBuildBehaviorAnalysis(SecurityEvent event) {
        String eventId = event.getEventId();

        SecurityPromptTemplate.BehaviorAnalysis cached = BEHAVIOR_ANALYSIS_CACHE.getIfPresent(eventId);
        if (cached != null) {
                        return cached;
        }

                BaseBehaviorAnalysis baseAnalysis = analyzeBehaviorPatterns(event);

        SecurityPromptTemplate.BehaviorAnalysis ctx = new SecurityPromptTemplate.BehaviorAnalysis();
        ctx.setSimilarEvents(baseAnalysis.getSimilarEvents());
        ctx.setBaselineContext(baseAnalysis.getBaselineContext());
        ctx.setBaselineEstablished(baseAnalysis.isBaselineEstablished());

        return ctx;
    }

    private List<Document> getCachedOrSearchRelatedContext(SecurityEvent event) {
        String eventId = event.getEventId();

        List<Document> cached = RAG_DOCUMENTS_CACHE.getIfPresent(eventId);
        if (cached != null) {
                        return cached;
        }

                return searchRelatedContext(event);
    }

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

    private int getPreviousBlocksForUser(String userId) {
        
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
                    }

        return 0;
    }

    private int getPreviousChallengesForUser(String userId) {
        
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
                    }

        return 0;
    }

    private SecurityResponse validateAndFixResponse(SecurityResponse response) {
        if (response == null) {
            return createDefaultResponse();
        }

        double[] validated = validateResponseBase(response.getRiskScore(), response.getConfidence());
        response.setRiskScore(validated[0]);
        response.setConfidence(validated[1]);

        return response;
    }

    private SecurityDecision extractLayer1Decision(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            log.warn("[Layer2] event or metadata is null, using default Layer1 decision");
            return createDefaultLayer1Decision();
        }

        Object layer1Result = event.getMetadata().get("layer1Assessment");
        if (layer1Result == null) {
                        return createDefaultLayer1Decision();
        }

        if (layer1Result instanceof ThreatAssessment layer1Assessment) {
            
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

    private SecurityDecision extractLayer2Decision(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            log.warn("[Layer2] event or metadata is null, using default Layer2 decision");
            return createDefaultLayer2Decision();
        }

        Object layer2Result = event.getMetadata().get("layer2Assessment");
        if (layer2Result == null) {
                        return createDefaultLayer2Decision();
        }

        if (layer2Result instanceof ThreatAssessment layer2Assessment) {
            
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

    private SecurityDecision convertToSecurityDecision(SecurityResponse response, SecurityEvent event) {
        
        if (response == null) {
            response = createDefaultResponse();
        }

        SecurityDecision.Action action = mapStringToAction(response.getAction());

        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
                .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                .reasoning(response.getReasoning())
                .eventId(event != null ? event.getEventId() : "unknown")
                .analysisTime(System.currentTimeMillis())
                .processingLayer(2)
                .llmModel("tier-2-auto-selected")  // 자동 상속 방식: tier 기반 자동 선택
                .build();

        if (response.getMitre() != null && !response.getMitre().isEmpty()) {
            Map<String, String> mitreMapping = new HashMap<>();
            mitreMapping.put(response.getMitre(), response.getMitre());
            decision.setMitreMapping(mitreMapping);
        }

        return decision;
    }

    private SecurityResponse parseJsonResponse(String jsonResponse) {
        
        SecurityResponse response = SecurityResponse.fromJson(jsonResponse);
        if (response == null) {
            log.error("Failed to parse JSON response from Layer2 LLM: {}", jsonResponse);
            return createDefaultResponse();
        }
        return validateAndFixResponse(response);
    }

    private SecurityResponse createDefaultResponse() {
        return SecurityResponse.builder()
                .riskScore(Double.NaN)  
                .confidence(Double.NaN)  
                .confidenceReasoning(null)  
                .action("ESCALATE")
                .reasoning("Layer 2 LLM analysis unavailable")
                .mitre(null)
                .build();
    }

    private String expandAction(String shortAction) {
        if (shortAction == null) return "ESCALATE";
        return switch (shortAction.toUpperCase()) {
            case "A" -> "ALLOW";
            case "E" -> "ESCALATE";
            case "B" -> "BLOCK";
            default -> shortAction;  
        };
    }

    private void executeSoarPlaybook(SecurityDecision decision, SecurityEvent event) {
        if (!enableSoar || decision.getSoarPlaybook() == null) {
            return;
        }

        try {
            log.warn("Executing SOAR playbook: {}", decision.getSoarPlaybook());

            List<Map<String, Object>> actions = new ArrayList<>();

            if (decision.getAction() == SecurityDecision.Action.BLOCK) {
                Map<String, Object> blockAction = Map.of(
                        "actionType", "BLOCK_IP",
                        "parameters", Map.of("ip", event.getSourceIp())
                );
                actions.add(blockAction);
            }

            if (decision.getIocIndicators() != null && !decision.getIocIndicators().isEmpty()) {
                Map<String, Object> investigateAction = Map.of(
                        "actionType", "INVESTIGATE_IOC",
                        "parameters", Map.of("iocs", decision.getIocIndicators())
                );
                actions.add(investigateAction);
            }

            Map<String, Object> notifyAction = Map.of(
                    "actionType", "NOTIFY_SOC",
                    "parameters", Map.of(
                            "severity", "CRITICAL",
                            "event", event.getEventId(),
                            "risk", decision.getRiskScore()
                    )
            );
            actions.add(notifyAction);

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

    private void handleApprovalProcess(SecurityDecision decision, SecurityEvent event) {
        if (approvalService == null) {
            log.warn("Approval service not available");
            return;
        }

        try {
            
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
                .action(SecurityDecision.Action.BLOCK)  
                .riskScore(Double.NaN)  
                .confidence(Double.NaN)  
                .analysisTime(startTime)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .processingLayer(2)
                .eventId(event != null ? event.getEventId() : "unknown")
                .reasoning("[AI Native] Layer 2 LLM analysis failed - applying failsafe blocking")
                .requiresApproval(true)
                .expertRecommendation("Manual review required - LLM analysis failed")
                .build();
    }

    private static class HistoricalContext {
        private List<String> similarIncidents = new ArrayList<>();
        private int previousAttacks;  
        private int previousChallenges;  

        public List<String> getSimilarIncidents() { return similarIncidents; }
        public void setSimilarIncidents(List<String> incidents) { this.similarIncidents = incidents; }

        public int getPreviousAttacks() { return previousAttacks; }
        public void setPreviousAttacks(int count) { this.previousAttacks = count; }

        public int getPreviousChallenges() { return previousChallenges; }
        public void setPreviousChallenges(int count) { this.previousChallenges = count; }
    }

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
        
        log.warn("[Layer2][AI Native] calculateRiskScore called without LLM - returning NaN");
        return Double.NaN;
    }

    private String mapActionToRecommendation(SecurityDecision.Action action) {
        return switch (action) {
            case ALLOW -> "ALLOW_WITH_MONITORING";
            case BLOCK -> "BLOCK_WITH_INCIDENT_RESPONSE";
            case CHALLENGE -> "REQUIRE_REAUTHENTICATION";
            case ESCALATE -> "ESCALATE_TO_SOC";
        };
    }

    private void storeInVectorDatabase(SecurityEvent event, SecurityDecision decision, SecurityResponse response) {
        if (unifiedVectorService == null) return;

        try {

            StringBuilder content = new StringBuilder();

            if (event.getUserId() != null) {
                content.append("User: ").append(event.getUserId());
            }

            if (event.getSourceIp() != null) {
                if (content.length() > 0) content.append(", ");
                content.append("IP: ").append(event.getSourceIp());
            }

            String path = eventEnricher.getTargetResource(event).orElse(null);
            if (path != null && !path.isEmpty()) {
                if (content.length() > 0) content.append(", ");
                content.append("Path: ").append(path);
            }

            String os = extractOSFromUserAgent(event.getUserAgent());
            if (os != null) {
                if (content.length() > 0) content.append(", ");
                content.append("OS: ").append(os);
            }

            Map<String, Object> metadata = new HashMap<>();

            metadata.put("documentType", VectorDocumentType.BEHAVIOR.getValue());
            if (event.getEventId() != null) {
                metadata.put("eventId", event.getEventId());
            }
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
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
                if (os != null) {
                    metadata.put("userAgentOS", os);
                }
                String browser = extractBrowserSignature(event.getUserAgent());
                if (browser != null) {
                    metadata.put("userAgentBrowser", browser);
                }
            }

            if (event.getTimestamp() != null) {
                metadata.put("hour", event.getTimestamp().getHour());
            }

            if (path != null && !path.isEmpty()) {
                metadata.put("requestPath", path);
            }

            if (decision.getThreatCategory() != null) {
                metadata.put("threatCategory", decision.getThreatCategory());
            }

            if (response.getMitre() != null && !response.getMitre().isEmpty()) {
                metadata.put("mitreTactic", response.getMitre());
            }

            Document document = new Document(content.toString(), metadata);
            unifiedVectorService.storeDocument(document);

            SecurityDecision.Action storeAction = decision.getAction();
            if (storeAction == SecurityDecision.Action.BLOCK) {
                storeThreatDocument(event, decision, response, content.toString());
            }

        } catch (Exception e) {
                    }
    }

    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, SecurityResponse response, String analysisContent) {
        try {
            
            Map<String, Object> threatMetadata = buildBaseMetadata(event, decision, VectorDocumentType.THREAT.getValue());

            if (response.getMitre() != null && !response.getMitre().isEmpty()) {
                threatMetadata.put("mitreTactic", response.getMitre());
            }

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

            Document threatDoc = new Document(threatDesc.toString(), threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

        } catch (Exception e) {
            log.warn("[Layer2] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }

    private void incrementAttackCount(String sourceIp) {
        if (redisTemplate == null || sourceIp == null || sourceIp.isEmpty()) {
            return;
        }

        try {
            String attackCountKey = ZeroTrustRedisKeys.attackCount(sourceIp);
            Long count = redisTemplate.opsForValue().increment(attackCountKey);
            redisTemplate.expire(attackCountKey, Duration.ofDays(7));
            
        } catch (Exception e) {
                    }
    }
}