package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.config.FeedbackConstants;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.response.Layer3SecurityResponse;
import io.contexa.contexacore.autonomous.tiered.template.Layer3PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.soar.approval.ApprovalRequestDetails;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.labs.AILabFactory;
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
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Layer 3: 전문가 시스템 전략
 *
 * 0.2%의 가장 복잡한 보안 이벤트를 1-5초 내에 처리하는 최종 방어선입니다.
 * Claude API 또는 고급 LLM을 사용하여 심층 분석을 수행하고 SOAR와 통합합니다.
 * 복잡한 공격 시나리오, 위협 인텔리전스, MITRE ATT&CK 매핑을 포함합니다.
 */
@Slf4j

public class Layer3ExpertStrategy extends AbstractTieredStrategy {

    private final UnifiedLLMOrchestrator llmOrchestrator;
    private final ApprovalService approvalService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityEventEnricher eventEnricher;
    private final Layer3PromptTemplate promptTemplate;

    private final BehaviorVectorService behaviorVectorService;
    private final FeedbackIntegrationProperties localFeedbackProperties;
    private final UnifiedVectorService unifiedVectorService;
    private final BaselineLearningService baselineLearningService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${spring.ai.security.layer3.model:llama3.1:8b}")
    private String modelName;

    @Value("${spring.ai.security.tiered.layer3.timeout-ms:30000}")
    private long timeoutMs;

    @Value("${spring.ai.security.tiered.layer3.enable-soar:false}")
    private boolean enableSoar;

    @Value("${spring.ai.security.tiered.layer3.rag.top-k:10}")
    private int ragTopK;

    @Value("${spring.ai.security.tiered.layer3.rag.threat-actor-similarity-threshold:0.7}")
    private double ragThreatActorSimilarityThreshold;

    @Value("${spring.ai.security.tiered.layer3.rag.campaign-similarity-threshold:0.65}")
    private double ragCampaignSimilarityThreshold;

    @Autowired
    public Layer3ExpertStrategy(@Autowired(required = false) UnifiedLLMOrchestrator llmOrchestrator,
                                @Autowired(required = false) ApprovalService approvalService,
                                @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                                @Autowired(required = false) SecurityEventEnricher eventEnricher,
                                @Autowired(required = false) Layer3PromptTemplate promptTemplate,
                                @Autowired(required = false) UnifiedVectorService unifiedVectorService,
                                @Autowired(required = false) BehaviorVectorService behaviorVectorService,
                                @Autowired FeedbackIntegrationProperties feedbackProperties,
                                @Autowired(required = false) BaselineLearningService baselineLearningService) {
        this.llmOrchestrator = llmOrchestrator;
        this.approvalService = approvalService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate : new Layer3PromptTemplate(eventEnricher);
        this.behaviorVectorService = behaviorVectorService;
        this.localFeedbackProperties = feedbackProperties;
        this.unifiedVectorService = unifiedVectorService;
        this.baselineLearningService = baselineLearningService;

        log.info("Layer 3 Expert Strategy initialized with UnifiedLLMOrchestrator");
        log.info("  - Model: {}", modelName);
        log.info("  - Timeout: {}ms", timeoutMs);
        log.info("  - SOAR Integration: {}", enableSoar);
        log.info("  - BaselineLearningService available: {}", baselineLearningService != null);
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.warn("Layer 3 Expert Strategy evaluating event: {}", event.getEventId());
        SecurityDecision layer2Decision = createDefaultLayer2Decision();
        SecurityDecision expertDecision = performDeepAnalysis(event, layer2Decision);
        String action = expertDecision.getAction() != null ? expertDecision.getAction().name() : "INVESTIGATE";

        return ThreatAssessment.builder()
                .riskScore(expertDecision.getRiskScore())
                .confidence(expertDecision.getConfidence())
                .threatLevel(null)
                .indicators(expertDecision.getIocIndicators())
                .recommendedActions(List.of(mapActionToRecommendation(expertDecision.getAction())))
                .strategyName("Layer3-Expert")
                .assessedAt(LocalDateTime.now())
                .shouldEscalate(false)  // Layer3는 최종 계층
                .action(action)  // AI Native: LLM action 직접 저장
                .build();
    }

    public SecurityDecision performDeepAnalysis(SecurityEvent event, SecurityDecision layer2Decision) {
        if (event == null) {
            log.error("Layer 3 analysis failed: event is null");
            return createFailsafeDecision(null, layer2Decision, System.currentTimeMillis());
        }

        if (layer2Decision == null) {
            log.warn("Layer 3 analysis: layer2Decision is null, creating default");
            layer2Decision = createDefaultLayer2Decision();
        }

        long startTime = System.currentTimeMillis();

        try {
            log.warn("[Layer3] Expert Analysis initiated for critical event {}",
                    event.getEventId() != null ? event.getEventId() : "unknown");

            ThreatIntelligence threatIntel = gatherThreatIntelligence(event);
            HistoricalContext historicalContext = analyzeHistoricalContext(event);
            SecurityDecision layer1Decision = createDefaultLayer1Decision();
            Layer3PromptTemplate.ThreatIntelligence threatIntelCtx = new Layer3PromptTemplate.ThreatIntelligence();
            threatIntelCtx.setKnownActors(threatIntel.getKnownActors() != null ?
                    String.join(", ", threatIntel.getKnownActors()) : "");
            threatIntelCtx.setRelatedCampaigns(threatIntel.getRelatedCampaigns() != null ?
                    String.join(", ", threatIntel.getRelatedCampaigns()) : "");
            threatIntelCtx.setIocMatches(threatIntel.getIocMatches() != null ?
                    String.join(", ", threatIntel.getIocMatches()) : "");

            Layer3PromptTemplate.HistoricalContext historicalCtx = new Layer3PromptTemplate.HistoricalContext();
            historicalCtx.setSimilarIncidents(historicalContext.getSimilarIncidents() != null ?
                    String.join(", ", historicalContext.getSimilarIncidents()) : "");
            historicalCtx.setPreviousAttacks(String.valueOf(historicalContext.getPreviousAttacks()));
            historicalCtx.setVulnerabilityHistory(historicalContext.getVulnerabilityHistory() != null ?
                    String.join(", ", historicalContext.getVulnerabilityHistory()) : "");

            String userId = event.getUserId();
            String baselineContext = null;
            if (baselineLearningService != null && userId != null) {
                baselineContext = baselineLearningService.buildBaselinePromptContext(userId, event);
                log.debug("[Layer3] Baseline context generated for user {}", userId);
            }

            // AI Native: 시스템 컨텍스트는 raw 데이터 부재 마커 사용
            // "UNKNOWN"은 플랫폼이 분류를 결정하는 것이므로 "[NOT_CLASSIFIED]" 사용
            Layer3PromptTemplate.SystemContext systemCtx = new Layer3PromptTemplate.SystemContext();
            systemCtx.setAssetCriticality("[NOT_CLASSIFIED]");
            systemCtx.setDataSensitivity("[NOT_CLASSIFIED]");

            String promptText = promptTemplate.buildPrompt(
                    event, layer1Decision, layer2Decision,
                    threatIntelCtx, historicalCtx, systemCtx,
                    baselineContext
            );

            Layer3SecurityResponse response = null;
            if (llmOrchestrator != null) {
                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(promptText))
                        .tier(3)
                        .preferredModel(modelName)
                        .securityTaskType(ExecutionContext.SecurityTaskType.EXPERT_INVESTIGATION)
                        .timeoutMs((int)timeoutMs)
                        .requestId(event.getEventId())
                        .build();

                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(timeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.warn("[Layer3][AI Native] LLM execution failed, applying failsafe blocking: {}", event.getEventId(), e);
                            // AI Native: 에러 복구 시에도 플랫폼 분류 금지 - "[NOT_CLASSIFIED]" 마커 사용
                            return Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"BLOCK\",\"classification\":\"[NOT_CLASSIFIED]\",\"scenario\":\"[AI Native] LLM execution failed - failsafe blocking applied\"}");
                        })
                        .block();

                response = parseJsonResponse(jsonResponse);
            } else {
                log.warn("UnifiedLLMOrchestrator not available for Layer 3 analysis");
                response = createDefaultResponse();
            }

            SecurityDecision expertDecision = convertToSecurityDecision(response, event, layer2Decision);

            if (enableSoar && expertDecision.getAction() == SecurityDecision.Action.BLOCK) {
//                executeSoarPlaybook(expertDecision, event);
            }

            if (expertDecision.isRequiresApproval() && approvalService != null) {
//                handleApprovalProcess(expertDecision, event);
            }

            // 10. 인시던트 생성 및 알림
//            createSecurityIncident(expertDecision, event);

            // 11. 벡터 스토어에 저장 (학습용)
            storeInVectorDatabase(event, expertDecision, response);

            SecurityDecision.Action expertAction = expertDecision.getAction();
            if (expertAction == SecurityDecision.Action.BLOCK ||
                expertAction == SecurityDecision.Action.MITIGATE) {
                String sourceIp = event.getSourceIp();
                if (sourceIp != null && !sourceIp.isEmpty()) {
                    // 공격 카운트 증가 및 IP 평판 하향
                    incrementAttackCount(sourceIp);
                }
            }

            // 12. Layer3 → Layer1 피드백 루프 (Cross-Layer Learning)
            feedbackToLayer1(event, expertDecision);

            // 13. 메트릭 업데이트
            expertDecision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            expertDecision.setProcessingLayer(3);

            log.warn("Layer 3 Expert Analysis completed in {}ms - Final Risk: {}, Action: {}",
                    expertDecision.getProcessingTimeMs(),
                    expertDecision.getRiskScore(),
                    expertDecision.getAction() != null ? expertDecision.getAction() : "UNKNOWN");

            return expertDecision;

        } catch (Exception e) {
            log.error("Layer 3 expert analysis failed for event {}",
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
                    log.error("Layer 3 async analysis failed or timed out", throwable);
                    return Mono.just(createFailsafeDecision(event, layer2Decision, System.currentTimeMillis()));
                });
    }

    private ThreatIntelligence gatherThreatIntelligence(SecurityEvent event) {
        ThreatIntelligence intel = new ThreatIntelligence();

        if (event == null) {
            intel.setKnownActors(new ArrayList<>());
            intel.setRelatedCampaigns(new ArrayList<>());
            intel.setIocMatches(new ArrayList<>());
            intel.setGeoLocation("Unknown");
            return intel;
        }

        String sourceIp = event.getSourceIp();

        try {
            CompletableFuture<List<String>> actorsFuture = CompletableFuture.supplyAsync(
                    () -> findKnownThreatActors(event));

            CompletableFuture<List<String>> campaignsFuture = CompletableFuture.supplyAsync(
                    () -> identifyRelatedCampaigns(event));

            // 모든 병렬 작업 완료 대기
            CompletableFuture.allOf(actorsFuture, campaignsFuture).join();

            List<String> knownActors = actorsFuture.get();
            if (knownActors.isEmpty()) {
                knownActors = new ArrayList<>();
                knownActors.add("[NO_KNOWN_ACTORS: first time observation]");
            }
            intel.setKnownActors(knownActors);

            List<String> relatedCampaigns = campaignsFuture.get();
            if (relatedCampaigns.isEmpty()) {
                relatedCampaigns = new ArrayList<>();
                relatedCampaigns.add("[NO_CAMPAIGNS: isolated incident or new pattern]");
            }
            intel.setRelatedCampaigns(relatedCampaigns);

            // AI Native: IOC는 LLM이 직접 분석, 플랫폼은 컨텍스트 제공 안 함
            intel.setIocMatches(new ArrayList<>());

            // AI Native: GeoLocation은 sourceIp raw 데이터로 충분, LLM이 직접 판단
            intel.setGeoLocation(sourceIp != null ? "IP: " + sourceIp : "Unknown");

        } catch (Exception e) {
            log.warn("[Layer3] Parallel threat intelligence gathering failed, using defaults", e);
            // AI Native: reputationScore 제거 - LLM이 IP 컨텍스트로 직접 판단
            intel.setKnownActors(List.of("[ERROR: threat actor lookup failed]"));
            intel.setRelatedCampaigns(List.of("[ERROR: campaign lookup failed]"));
            intel.setIocMatches(List.of("[ERROR: IOC lookup failed]"));
            intel.setGeoLocation("Unknown");
        }

        return intel;
    }

    /**
     * 알려진 위협 액터 찾기 (UnifiedVectorService RAG 기반)
     */
    private List<String> findKnownThreatActors(SecurityEvent event) {
        List<String> actors = new ArrayList<>();

        if (unifiedVectorService != null) {
            try {
                String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
                String sourceIp = event.getSourceIp() != null ? event.getSourceIp() : "unknown";
                String attackVector = event.getAttackVector() != null ? event.getAttackVector() : "";

                String query = String.format("threat-actor %s %s IP:%s", eventType, attackVector, sourceIp);

                // AI Native: RAG 검색 파라미터는 설정에서 주입 (하드코딩 금지)
                org.springframework.ai.vectorstore.SearchRequest searchRequest =
                    org.springframework.ai.vectorstore.SearchRequest.builder()
                        .query(query)
                        .topK(ragTopK)
                        .similarityThreshold(ragThreatActorSimilarityThreshold)
                        .build();

                List<Document> threatDocs = unifiedVectorService.searchSimilar(searchRequest);

                if (threatDocs != null && !threatDocs.isEmpty()) {
                    actors = threatDocs.stream()
                        .map(doc -> {
                            Map<String, Object> meta = doc.getMetadata();
                            String actor = (String) meta.get("threatActor");
                            Object scoreObj = meta.get("confidence");
                            if (actor != null && !actor.isBlank()) {
                                if (scoreObj instanceof Number) {
                                    double score = ((Number) scoreObj).doubleValue();
                                    return String.format("%s (confidence: %.2f, RAG)", actor, score);
                                }
                                return actor + " (RAG)";
                            }
                            return null;
                        })
                        .filter(Objects::nonNull)
                        .limit(5)
                        .collect(Collectors.toList());

                    log.debug("RAG threat actor search: {} actors found", actors.size());
                }
            } catch (Exception e) {
                log.warn("UnifiedVectorService threat actor search failed: {}", e.getMessage());
            }
        }

        if (actors.isEmpty()) {
            actors = findKnownThreatActorsFallback(event);
        }

        return actors;
    }

    private List<String> findKnownThreatActorsFallback(SecurityEvent event) {
        log.warn("[Layer3][AI Native] Vector service unavailable, threat actor detection delegated to LLM");
        return new ArrayList<>();
    }

    private List<String> identifyRelatedCampaigns(SecurityEvent event) {
        List<String> campaigns = new ArrayList<>();

        if (unifiedVectorService != null) {
            try {
                String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
                Optional<String> targetResource = eventEnricher.getTargetResource(event);
                String mitreId = event.getMitreAttackId() != null ? event.getMitreAttackId() : "";

                String campaignQuery = String.format("campaign %s targeting %s %s",
                        eventType, targetResource.orElse("unknown"), mitreId);

                // AI Native: RAG 검색 파라미터는 설정에서 주입 (하드코딩 금지)
                org.springframework.ai.vectorstore.SearchRequest searchRequest =
                    org.springframework.ai.vectorstore.SearchRequest.builder()
                        .query(campaignQuery)
                        .topK(ragTopK)
                        .similarityThreshold(ragCampaignSimilarityThreshold)
                        .build();

                List<Document> campaignDocs = unifiedVectorService.searchSimilar(searchRequest);

                if (campaignDocs != null && !campaignDocs.isEmpty()) {
                    campaigns = campaignDocs.stream()
                        .map(doc -> {
                            Map<String, Object> meta = doc.getMetadata();
                            String campaignId = (String) meta.get("campaignId");
                            String campaignName = (String) meta.get("campaignName");
                            Object similarityObj = meta.get("similarity");

                            if (campaignName != null && !campaignName.isBlank()) {
                                if (similarityObj instanceof Number) {
                                    double similarity = ((Number) similarityObj).doubleValue();
                                    return String.format("%s (%s, similarity: %.2f, RAG)",
                                        campaignName, campaignId != null ? campaignId : "unknown", similarity);
                                }
                                return String.format("%s (RAG)", campaignName);
                            }
                            return null;
                        })
                        .filter(Objects::nonNull)
                        .limit(5)
                        .collect(Collectors.toList());

                    log.debug("RAG campaign search: {} campaigns found", campaigns.size());
                }
            } catch (Exception e) {
                log.warn("UnifiedVectorService campaign search failed: {}", e.getMessage());
            }
        }

        return campaigns;
    }

    /**
     * 과거 컨텍스트 분석
     */
    private HistoricalContext analyzeHistoricalContext(SecurityEvent event) {
        HistoricalContext context = new HistoricalContext();

        // Null safety: event가 null인 경우 기본값 설정
        if (event == null) {
            context.setSimilarIncidents(new ArrayList<>());
            context.setPreviousAttacks(0);
            context.setVulnerabilityHistory(new ArrayList<>());
            return context;
        }

        // 유사 인시던트 조회
        List<String> similarIncidents = findSimilarIncidents(event);
        if (similarIncidents.isEmpty()) {
            similarIncidents.add("[NEW_THREAT: no similar historical incidents]");
        }
        context.setSimilarIncidents(similarIncidents);

        // 소스로부터의 이전 공격 (null-safe)
        String sourceIp = event.getSourceIp();
        int previousAttacks = getPreviousAttacksFromSource(sourceIp);
        if (previousAttacks == 0) {
            // Note: zero attack count는 정상 값이므로 컨텍스트만 추가
            context.setPreviousAttacks(0);
        } else {
            context.setPreviousAttacks(previousAttacks);
        }

        context.setVulnerabilityHistory(new ArrayList<>());

        return context;
    }

    /**
     * 유사 인시던트 찾기 (Vector-based with fallback)
     */
    private List<String> findSimilarIncidents(SecurityEvent event) {
        if (behaviorVectorService == null) {
            return findSimilarIncidentsFallback(event);
        }

        try {
            String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
            String sourceIp = event.getSourceIp() != null ? event.getSourceIp() : "unknown";
            Optional<String> targetResource = eventEnricher.getTargetResource(event);

            String incidentQuery = String.format("security incident %s from %s targeting %s",
                    eventType,
                    sourceIp,
                    targetResource.orElse("unknown"));

            List<Document> similarIncidents = behaviorVectorService.findSimilarBehaviors(
                    sourceIp,
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

        // Null safety: event가 null이거나 eventType이 null인 경우 빈 리스트 반환
        if (event == null || event.getEventType() == null) {
            return incidents;
        }

        if (redisTemplate == null) {
            return incidents;
        }

        String pattern = "incident:*:" + event.getEventType();
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
            log.debug("[Layer3] Failed to find similar incidents via SCAN for event type: {}",
                    event.getEventType(), e);
        }

        return incidents;
    }

    /**
     * 소스로부터의 이전 공격 조회
     */
    private int getPreviousAttacksFromSource(String sourceIp) {
        // Null safety: sourceIp가 null인 경우 0 반환
        if (sourceIp == null || sourceIp.trim().isEmpty()) {
            return 0;
        }

        if (redisTemplate == null) {
            return 0;
        }

        try {
            String attackCountKey = ZeroTrustRedisKeys.attackCount(sourceIp);
            Object count = redisTemplate.opsForValue().get(attackCountKey);
            if (count != null) {
                return Integer.parseInt(count.toString());
            }
        } catch (Exception e) {
            log.debug("Failed to get previous attacks count for IP: {}", sourceIp, e);
        }

        return 0;
    }

    private Layer3SecurityResponse validateAndFixResponse(Layer3SecurityResponse response) {
        if (response == null) {
            return createDefaultResponse();
        }

        // AI Native: confidence가 null이면 NaN 사용 (강제 상향 금지)
        if (response.getConfidence() == null) {
            log.warn("[Layer3][AI Native] LLM이 confidence 미반환 (가공 없이 NaN 사용)");
            response.setConfidence(Double.NaN);
        }

        // AI Native: riskScore가 null이면 NaN 사용 (기본값 금지)
        if (response.getRiskScore() == null) {
            log.warn("[Layer3][AI Native] LLM이 riskScore 미반환 (가공 없이 NaN 사용)");
            response.setRiskScore(Double.NaN);
        }

        // AI Native: classification이 null이면 마커 표시 (플랫폼 분류 금지)
        // "UNKNOWN_THREAT"는 플랫폼이 위협 유형을 결정하는 것이므로 위반
        if (response.getClassification() == null || response.getClassification().isBlank()) {
            response.setClassification("[NOT_CLASSIFIED]");
        }

        // tactics 검증
        if (response.getTactics() == null) {
            response.setTactics(new ArrayList<>());
        }

        // techniques 검증
        if (response.getTechniques() == null) {
            response.setTechniques(new ArrayList<>());
        }

        // iocIndicators 검증
        if (response.getIocIndicators() == null) {
            response.setIocIndicators(new ArrayList<>());
        }

        return response;
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

    private SecurityDecision convertToSecurityDecision(Layer3SecurityResponse response,
                                                       SecurityEvent event,
                                                       SecurityDecision layer2Decision) {
        // Null safety: response가 null인 경우 기본 응답 생성
        if (response == null) {
            response = createDefaultResponse();
        }

        SecurityDecision.Action action = mapStringToAction(response.getAction());

        // AI Native: LLM 응답 그대로 사용, null이면 NaN
        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
                .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                .attackScenario(response.getScenario())
                .businessImpact(response.getBusinessImpact())
                .reasoning(response.getReasoning())
                .expertRecommendation(response.getExpertRecommendation())
                .requiresApproval(response.getRequiresApproval() != null ? response.getRequiresApproval() : false)
                .soarPlaybook(response.getPlaybookId())
                .eventId(event != null ? event.getEventId() : "unknown")
                .analysisTime(System.currentTimeMillis())
                .processingLayer(3)
                .llmModel(modelName)
                .build();

        if (response.getTactics() != null) {
            Map<String, String> mitreMapping = new HashMap<>();
            for (String tactic : response.getTactics()) {
                // MITRE_TACTICS 제거로 인해 간단한 매핑만 수행
                mitreMapping.put(tactic, tactic);
            }
            decision.setMitreMapping(mitreMapping);
        }

        if (response.getIocIndicators() != null) {
            decision.setIocIndicators(response.getIocIndicators());
        }

        return decision;
    }

    private Layer3SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            String cleanedJson = extractJsonObject(jsonResponse);
            JsonNode jsonNode = objectMapper.readTree(cleanedJson);

            // Phase 12: 통일된 출력 형식 지원 (r/c/a/d + 하위호환)
            // 단축 필드(r,c,a,d) 우선, 없으면 긴 필드명(riskScore, confidence, action, reasoning)
            Double riskScore = jsonNode.has("r") ? jsonNode.get("r").asDouble()
                : (jsonNode.has("riskScore") ? jsonNode.get("riskScore").asDouble() : Double.NaN);
            Double confidence = jsonNode.has("c") ? jsonNode.get("c").asDouble()
                : (jsonNode.has("confidence") ? jsonNode.get("confidence").asDouble() : Double.NaN);
            String action = jsonNode.has("a") ? expandAction(jsonNode.get("a").asText())
                : (jsonNode.has("action") ? jsonNode.get("action").asText() : "ESCALATE");
            String reasoning = jsonNode.has("d") ? jsonNode.get("d").asText()
                : (jsonNode.has("reasoning") ? jsonNode.get("reasoning").asText() : "No reasoning");

            String classification = jsonNode.has("classification") ? jsonNode.get("classification").asText() : "UNKNOWN";
            String scenario = jsonNode.has("scenario") ? jsonNode.get("scenario").asText() : "No scenario";
            String threatActor = jsonNode.has("threatActor") ? jsonNode.get("threatActor").asText() : "UNKNOWN";
            String expertRecommendation = jsonNode.has("expertRecommendation") ? jsonNode.get("expertRecommendation").asText() : "Manual investigation required";

            // 배열 파싱
            List<String> tactics = new ArrayList<>();
            if (jsonNode.has("tactics") && jsonNode.get("tactics").isArray()) {
                jsonNode.get("tactics").forEach(node -> tactics.add(node.asText()));
            }

            List<String> techniques = new ArrayList<>();
            if (jsonNode.has("techniques") && jsonNode.get("techniques").isArray()) {
                jsonNode.get("techniques").forEach(node -> techniques.add(node.asText()));
            }

            List<String> iocIndicators = new ArrayList<>();
            if (jsonNode.has("iocIndicators") && jsonNode.get("iocIndicators").isArray()) {
                jsonNode.get("iocIndicators").forEach(node -> iocIndicators.add(node.asText()));
            }

            // Response 객체 생성
            Layer3SecurityResponse response = Layer3SecurityResponse.builder()
                    .riskScore(riskScore)
                    .confidence(confidence)
                    .action(action)
                    .classification(classification)
                    .scenario(scenario)
                    .reasoning(reasoning)
                    .threatActor(threatActor)
                    .expertRecommendation(expertRecommendation)
                    .tactics(tactics)
                    .techniques(techniques)
                    .iocIndicators(iocIndicators)
                    .stage("UNKNOWN")
                    .businessImpact("Unknown impact")
                    .playbookId("default-incident-response")
                    .requiresApproval(true)
                    .mitreMapping(new HashMap<>())
                    .build();

            return validateAndFixResponse(response);

        } catch (Exception e) {
            log.error("Failed to parse JSON response from Layer3 LLM: {}", jsonResponse, e);
            return createDefaultResponse();
        }
    }

    private Layer3SecurityResponse createDefaultResponse() {
        return Layer3SecurityResponse.builder()
                .riskScore(Double.NaN)  // AI Native: LLM 분석 미수행
                .confidence(Double.NaN)  // AI Native: LLM 분석 미수행
                .action("ESCALATE")
                .classification("UNKNOWN")
                .scenario("Analysis unavailable")
                .stage("UNKNOWN")
                .tactics(new ArrayList<>())
                .techniques(new ArrayList<>())
                .iocIndicators(new ArrayList<>())
                .threatActor("UNKNOWN")
                .businessImpact("Unknown impact")
                .playbookId("default-incident-response")
                .requiresApproval(true)
                .reasoning("[AI Native] Layer 3 LLM analysis unavailable")
                .expertRecommendation("Manual investigation required - LLM analysis not performed")
                .mitreMapping(new HashMap<>())
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

    /**
     * 문자열을 액션으로 매핑
     *
     * AI Native: 알 수 없는 action은 INVESTIGATE (Zero Trust)
     * - Layer3는 최종 계층이므로 ESCALATE 불가
     * - MONITOR는 플랫폼이 임의로 결정하는 것이므로 위반
     * - 불확실 시 INVESTIGATE하여 인간 개입 요청
     */
    private SecurityDecision.Action mapStringToAction(String action) {
        if (action == null) return SecurityDecision.Action.INVESTIGATE;
        return switch (action.toUpperCase()) {
            case "ALLOW" -> SecurityDecision.Action.ALLOW;
            case "BLOCK" -> SecurityDecision.Action.BLOCK;
            case "MITIGATE" -> SecurityDecision.Action.MITIGATE;
            case "INVESTIGATE" -> SecurityDecision.Action.INVESTIGATE;
            case "ESCALATE" -> SecurityDecision.Action.ESCALATE;
            case "MONITOR" -> SecurityDecision.Action.MONITOR;  // LLM이 명시적으로 MONITOR 반환한 경우만
            default -> SecurityDecision.Action.INVESTIGATE;  // AI Native: 최종 계층 - 불확실 시 조사 요청
        };
    }


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
                    .detectedBy("Layer3ExpertSystem")
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
                .processingLayer(3)
                .eventId(event != null ? event.getEventId() : "unknown")
                .reasoning("[AI Native] Layer 3 LLM analysis failed - applying failsafe blocking")
                .requiresApproval(true)
                .expertRecommendation("Manual review required - LLM analysis failed")
                .build();
    }

    private static class ThreatIntelligence {
        private List<String> knownActors = new ArrayList<>();
        private List<String> relatedCampaigns = new ArrayList<>();
        private List<String> iocMatches = new ArrayList<>();
        private String geoLocation;

        public List<String> getKnownActors() { return knownActors; }
        public void setKnownActors(List<String> actors) { this.knownActors = actors; }

        public List<String> getRelatedCampaigns() { return relatedCampaigns; }
        public void setRelatedCampaigns(List<String> campaigns) { this.relatedCampaigns = campaigns; }

        public List<String> getIocMatches() { return iocMatches; }
        public void setIocMatches(List<String> iocs) { this.iocMatches = iocs; }

        public String getGeoLocation() { return geoLocation != null ? geoLocation : "Unknown"; }
        public void setGeoLocation(String location) { this.geoLocation = location; }
    }

    private static class HistoricalContext {
        private List<String> similarIncidents = new ArrayList<>();
        private int previousAttacks;
        private List<String> vulnerabilityHistory = new ArrayList<>();

        // Getters and setters
        public List<String> getSimilarIncidents() { return similarIncidents; }
        public void setSimilarIncidents(List<String> incidents) { this.similarIncidents = incidents; }

        public int getPreviousAttacks() { return previousAttacks; }
        public void setPreviousAttacks(int count) { this.previousAttacks = count; }

        public List<String> getVulnerabilityHistory() { return vulnerabilityHistory; }
        public void setVulnerabilityHistory(List<String> history) { this.vulnerabilityHistory = history; }
    }

    private void feedbackToLayer1(SecurityEvent event, SecurityDecision decision) {
        if (redisTemplate == null) {
            return;
        }

        // AI Native: Action 기반 피드백 결정
        // Action이 null이거나 ALLOW인 경우 피드백 불필요
        SecurityDecision.Action action = decision.getAction();
        if (action == null || action == SecurityDecision.Action.ALLOW) {
            return;
        }

        try {
            String feedbackKey = "layer3:feedback:" + event.getEventId();

            Map<String, Object> feedback = new HashMap<>();
            feedback.put("eventId", event.getEventId());
            feedback.put("userId", event.getUserId() != null ? event.getUserId() : FeedbackConstants.DEFAULT_USER_ID);
            feedback.put("sourceIp", event.getSourceIp());
            feedback.put("eventType", event.getEventType() != null ? event.getEventType().toString() : FeedbackConstants.DEFAULT_EVENT_TYPE);
            feedback.put("riskScore", decision.getRiskScore());
            feedback.put("confidence", decision.getConfidence());
            feedback.put("action", action.toString());
            feedback.put("threatCategory", decision.getThreatCategory());
            feedback.put("mitreTactics", decision.getMitreMapping() != null ? new ArrayList<>(decision.getMitreMapping().keySet()) : List.of());
            feedback.put("iocIndicators", decision.getIocIndicators());
            feedback.put("timestamp", System.currentTimeMillis());

            storeFeedbackWithRetry(feedbackKey, feedback);

            String patternKey = localFeedbackProperties.getRedis().getPatternKeyPrefix() + event.getEventType();
            redisTemplate.opsForList().rightPush(patternKey, feedback);
            redisTemplate.expire(patternKey, Duration.ofDays(30));

            log.info("[Layer3] Feedback stored: eventId={}, action={}", event.getEventId(), action);

        } catch (Exception e) {
            log.warn("[Layer3] Failed to store feedback: eventId={}", event.getEventId(), e);
        }
    }

    /**
     * Redis 저장 실패 시 자동 재시도 (최대 3회, exponential backoff)
     */
    @Retryable(
            value = {Exception.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 1000, multiplier = 2)
    )
    private void storeFeedbackWithRetry(String feedbackKey, Map<String, Object> feedback) {
        try {
            redisTemplate.opsForValue().set(feedbackKey, feedback, Duration.ofDays(7));
            log.debug("Feedback stored successfully: key={}", feedbackKey);
        } catch (Exception e) {
            log.error("Failed to store feedback (will retry): key={}", feedbackKey, e);
            throw e;
        }
    }

    /**
     * AbstractTieredStrategy의 getLayerName() 구현
     */
    @Override
    protected String getLayerName() {
        return "Layer3";
    }

    @Override
    public String getStrategyName() {
        return "Layer3-Expert-Strategy";
    }

    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        // ThreatIndicator 추출 로직
        return new ArrayList<>();
    }

    // ThreatEvaluationStrategy 인터페이스에서 mapToFramework 제거됨
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        mapping.put("framework", "EXPERT_ANALYSIS");
        mapping.put("tier", "3");
        // MITRE ATT&CK 매핑 추가
        if (event.getMitreAttackId() != null) {
            mapping.put("mitre_attack", event.getMitreAttackId());
        }
        return mapping;
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
        log.warn("[Layer3][AI Native] calculateRiskScore called without LLM - returning NaN");
        return Double.NaN;
    }

    private String mapActionToRecommendation(SecurityDecision.Action action) {
        return switch (action) {
            case BLOCK -> "BLOCK_WITH_INCIDENT_RESPONSE";
            case MITIGATE -> "APPLY_ADVANCED_MITIGATION";
            case INVESTIGATE -> "DEEP_FORENSIC_INVESTIGATION";
            case ESCALATE -> "ESCALATE_TO_SOC";
            default -> "EXPERT_REVIEW_REQUIRED";
        };
    }

    /**
     * 벡터 데이터베이스에 저장
     */
    private void storeInVectorDatabase(SecurityEvent event, SecurityDecision decision, Layer3SecurityResponse response) {
        if (unifiedVectorService == null) return;

        try {
            // 심층 분석 결과 문서 생성
            String content = String.format(
                    "Event: %s, Risk: %.2f, Action: %s, Classification: %s, MITRE: %s, Reasoning: %s",
                    event.getEventType(),
                    decision.getRiskScore(),
                    decision.getAction(),
                    response.getClassification(),
                    response.getTactics() != null ? String.join(",", response.getTactics()) : "",
                    decision.getReasoning()
            );

            // Spring AI Document는 null 값을 허용하지 않으므로 기본값 설정 필수
            Map<String, Object> metadata = new HashMap<>();

            // 필수 공통 metadata
            metadata.put("documentType", VectorDocumentType.BEHAVIOR.getValue());
            metadata.put("eventId", event.getEventId() != null ? event.getEventId() : "unknown");
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            metadata.put("userId", event.getUserId() != null ? event.getUserId() : "unknown");

            // SecurityEvent 정보
            metadata.put("eventType", event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN");
            metadata.put("sourceIp", event.getSourceIp() != null ? event.getSourceIp() : "unknown");
            metadata.put("sessionId", event.getSessionId() != null ? event.getSessionId() : "unknown");

            // SecurityDecision 정보
            // AI Native: NaN은 metadata에 저장 불가 - Double.NaN 체크 후 -1.0으로 대체 (메타데이터 전용)
            double metaRiskScore = decision.getRiskScore();
            double metaConfidence = decision.getConfidence();
            metadata.put("riskScore", Double.isNaN(metaRiskScore) ? -1.0 : metaRiskScore);
            metadata.put("action", decision.getAction() != null ? decision.getAction().toString() : "INVESTIGATE");
            metadata.put("confidence", Double.isNaN(metaConfidence) ? -1.0 : metaConfidence);
            metadata.put("threatCategory", decision.getThreatCategory() != null ? decision.getThreatCategory() : "[NOT_CLASSIFIED]");

            // Layer3 전문가 분석 결과
            metadata.put("classification", response.getClassification() != null ? response.getClassification() : "[NOT_CLASSIFIED]");
            if (response.getTactics() != null && !response.getTactics().isEmpty()) {
                metadata.put("tactics", String.join(",", response.getTactics()));
            }
            if (response.getTechniques() != null && !response.getTechniques().isEmpty()) {
                metadata.put("techniques", String.join(",", response.getTechniques()));
            }
            if (response.getIocIndicators() != null && !response.getIocIndicators().isEmpty()) {
                metadata.put("iocIndicators", String.join(",", response.getIocIndicators()));
            }

            SecurityDecision.Action storeAction = decision.getAction();
            if (response.getThreatActor() != null && !response.getThreatActor().isEmpty()) {
                metadata.put("threatActor", response.getThreatActor());
            }
            if (response.getTactics() != null && !response.getTactics().isEmpty()) {
                metadata.put("mitreTactic", response.getTactics().get(0));
            }

            Document document = new Document(content, metadata);
            unifiedVectorService.storeDocument(document);

            if (storeAction == SecurityDecision.Action.BLOCK ||
                storeAction == SecurityDecision.Action.MITIGATE) {
                storeThreatDocument(event, decision, response, content);
            }

        } catch (Exception e) {
            log.debug("Failed to store in vector database", e);
        }
    }

    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, Layer3SecurityResponse response, String analysisContent) {
        try {
            Map<String, Object> threatMetadata = new HashMap<>();

            // 위협 전용 documentType
            threatMetadata.put("documentType", VectorDocumentType.THREAT.getValue());
            threatMetadata.put("riskScore", decision.getRiskScore());

            // 기본 정보
            threatMetadata.put("eventId", event.getEventId());
            threatMetadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            threatMetadata.put("userId", event.getUserId() != null ? event.getUserId() : "unknown");
            threatMetadata.put("eventType", event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN");
            threatMetadata.put("sourceIp", event.getSourceIp());
            threatMetadata.put("sessionId", event.getSessionId());

            threatMetadata.put("threatType", determineThreatType(response));
            threatMetadata.put("threatCategory", decision.getThreatCategory() != null ? decision.getThreatCategory() : response.getClassification());

            // Layer3 전문가 분석 특화 정보
            if (response.getClassification() != null) {
                threatMetadata.put("expertClassification", response.getClassification());
            }
            if (response.getTactics() != null && !response.getTactics().isEmpty()) {
                threatMetadata.put("mitreTactics", String.join(", ", response.getTactics()));
            }
            if (response.getTechniques() != null && !response.getTechniques().isEmpty()) {
                threatMetadata.put("mitreTechniques", String.join(", ", response.getTechniques()));
            }
            if (response.getIocIndicators() != null && !response.getIocIndicators().isEmpty()) {
                threatMetadata.put("iocIndicators", String.join(", ", response.getIocIndicators()));
            }
            if (response.getThreatActor() != null) {
                threatMetadata.put("threatActor", response.getThreatActor());
            }

            // MITRE ATT&CK (LLM 응답에서 가져온 값만 저장)
            if (response.getTactics() != null && !response.getTactics().isEmpty()) {
                threatMetadata.put("mitreTactic", response.getTactics().get(0));
            }

            // LLM 결정 정보
            threatMetadata.put("confidence", decision.getConfidence());
            threatMetadata.put("action", decision.getAction().toString());

            // 위협 설명 (전문가 분석 포함)
            String threatDescription = String.format(
                "Layer3 Expert Threat Confirmation: User=%s, EventType=%s, IP=%s, RiskScore=%.2f, " +
                "Classification=%s, Tactics=%s, Techniques=%s, IOC=%s, Action=%s, Reasoning=%s",
                event.getUserId(), event.getEventType(), event.getSourceIp(),
                decision.getRiskScore(),
                response.getClassification(),
                response.getTactics() != null ? response.getTactics() : "[]",
                response.getTechniques() != null ? response.getTechniques() : "[]",
                response.getIocIndicators() != null ? response.getIocIndicators() : "[]",
                decision.getAction(),
                decision.getReasoning() != null ? decision.getReasoning().substring(0, Math.min(150, decision.getReasoning().length())) : ""
            );

            Document threatDoc = new Document(threatDescription, threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

            log.info("[Layer3] 위협 패턴 저장 완료 (전문가 확정): userId={}, riskScore={}, classification={}, tactics={}",
                event.getUserId(), decision.getRiskScore(), response.getClassification(),
                response.getTactics() != null ? response.getTactics().size() : 0);

        } catch (Exception e) {
            log.warn("[Layer3] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }
    private String determineThreatType(Layer3SecurityResponse response) {
        // AI Native: LLM이 반환한 classification 그대로 사용
        if (response.getClassification() != null && !response.getClassification().isEmpty()) {
            return response.getClassification();
        }

        return null;
    }
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