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
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.soar.approval.ApprovalRequestDetails;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
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
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
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
    private final HCADVectorIntegrationService localHcadVectorService;
    private final BehaviorVectorService behaviorVectorService;
    private final FeedbackIntegrationProperties localFeedbackProperties;
    private final UnifiedVectorService unifiedVectorService;
    private final ObjectMapper objectMapper = new ObjectMapper();



    @Value("${ai.security.tiered.layer3.model:llama3.1:8b}")
    private String modelName;

    @Value("${ai.security.tiered.layer3.timeout-ms:5000}")
    private long timeoutMs;

    @Value("${ai.security.tiered.layer3.enable-soar:true}")
    private boolean enableSoar;

    @Value("${ai.security.tiered.layer3.auto-execute-threshold:0.95}")
    private double autoExecuteThreshold;

    @Autowired
    public Layer3ExpertStrategy(@Autowired(required = false) UnifiedLLMOrchestrator llmOrchestrator,
                                @Autowired(required = false) AILabFactory labFactory,
                                @Autowired(required = false) ApprovalService approvalService,
                                @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
                                @Autowired(required = false) SecurityEventEnricher eventEnricher,
                                @Autowired(required = false) Layer3PromptTemplate promptTemplate,
                                @Autowired(required = false) HCADVectorIntegrationService hcadVectorService,
                                @Autowired(required = false) BehaviorVectorService behaviorVectorService,
                                @Autowired FeedbackIntegrationProperties feedbackProperties,
                                @Autowired(required = false) UnifiedVectorService unifiedVectorService) {
        this.llmOrchestrator = llmOrchestrator;
        this.approvalService = approvalService;
        this.redisTemplate = redisTemplate;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate : new Layer3PromptTemplate(eventEnricher);
        this.localHcadVectorService = hcadVectorService;
        this.behaviorVectorService = behaviorVectorService;
        this.localFeedbackProperties = feedbackProperties;
        this.unifiedVectorService = unifiedVectorService;

        // AbstractTieredStrategy의 protected 필드 설정
        this.hcadVectorService = hcadVectorService;
        this.feedbackProperties = feedbackProperties;

        log.info("Layer 3 Expert Strategy initialized with UnifiedLLMOrchestrator");
        log.info("  - Model: {}", modelName);
        log.info("  - Timeout: {}ms", timeoutMs);
        log.info("  - SOAR Integration: {}", enableSoar);
    }

    /**
     * ThreatEvaluationStrategy 인터페이스 구현
     * ColdPathEventProcessorRefactored 에서 전략으로 사용됨
     *
     * AI Native 전환:
     * - Layer3는 최종 계층이므로 shouldEscalate = false
     * - LLM이 threatLevel을 직접 결정 (규칙 기반 매핑 제거)
     */
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.warn("Layer 3 Expert Strategy evaluating event: {}", event.getEventId());

        // 기본 Layer2 결정 생성
        SecurityDecision layer2Decision = createDefaultLayer2Decision();

        // 전문가 분석 실행
        SecurityDecision expertDecision = performDeepAnalysis(event, layer2Decision);

        // AI Native: Layer3는 최종 계층이므로 shouldEscalate = false
        // SecurityDecision을 ThreatAssessment로 변환
        return ThreatAssessment.builder()
                .riskScore(expertDecision.getRiskScore())
                .confidence(expertDecision.getConfidence())
                // AI Native: LLM이 threatLevel을 직접 결정
                .threatLevel(null)
                .indicators(expertDecision.getIocIndicators())
                .recommendedActions(List.of(mapActionToRecommendation(expertDecision.getAction())))
                .strategyName("Layer3-Expert")
                .assessedAt(LocalDateTime.now())
                .shouldEscalate(false)  // Layer3는 최종 계층
                .build();
    }

    /**
     * 심층 전문가 분석 수행
     *
     * @param event 보안 이벤트
     * @param layer2Decision Layer 2의 결정
     * @return 전문가 수준의 보안 결정
     */
    public SecurityDecision performDeepAnalysis(SecurityEvent event, SecurityDecision layer2Decision) {
        // Null safety: 입력 파라미터 검증
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

            // 1. 위협 인텔리전스 수집
            ThreatIntelligence threatIntel = gatherThreatIntelligence(event);

            // 2. 과거 인시던트 분석
            HistoricalContext historicalContext = analyzeHistoricalContext(event);

            // 3. 시스템 컨텍스트 평가
            SystemContext systemContext = evaluateSystemContext(event);


            // 5. PromptTemplate을 통한 프롬프트 구성
            SecurityDecision layer1Decision = createDefaultLayer1Decision();

            // 직접 변환 (중복 메서드 제거) - Null safety 적용
            Layer3PromptTemplate.ThreatIntelligence threatIntelCtx = new Layer3PromptTemplate.ThreatIntelligence();
            threatIntelCtx.setKnownActors(threatIntel != null && threatIntel.getKnownActors() != null ?
                    String.join(", ", threatIntel.getKnownActors()) : "");
            threatIntelCtx.setRelatedCampaigns(threatIntel != null && threatIntel.getRelatedCampaigns() != null ?
                    String.join(", ", threatIntel.getRelatedCampaigns()) : "");
            threatIntelCtx.setIocMatches(threatIntel != null && threatIntel.getIocMatches() != null ?
                    String.join(", ", threatIntel.getIocMatches()) : "");
            threatIntelCtx.setReputationScore(threatIntel != null ?
                    threatIntel.getReputationScore() : 0.5);

            Layer3PromptTemplate.HistoricalContext historicalCtx = new Layer3PromptTemplate.HistoricalContext();
            historicalCtx.setSimilarIncidents(historicalContext != null && historicalContext.getSimilarIncidents() != null ?
                    String.join(", ", historicalContext.getSimilarIncidents()) : "");
            historicalCtx.setPreviousAttacks(historicalContext != null ?
                    String.valueOf(historicalContext.getPreviousAttacks()) : "0");
            historicalCtx.setVulnerabilityHistory(historicalContext != null && historicalContext.getVulnerabilityHistory() != null ?
                    String.join(", ", historicalContext.getVulnerabilityHistory()) : "");

            Layer3PromptTemplate.SystemContext systemCtx = new Layer3PromptTemplate.SystemContext();
            systemCtx.setAssetCriticality(systemContext != null && systemContext.getAssetCriticality() != null ?
                    systemContext.getAssetCriticality() : "MEDIUM");
            systemCtx.setDataSensitivity(systemContext != null && systemContext.getDataSensitivity() != null ?
                    systemContext.getDataSensitivity() : "INTERNAL");
            systemCtx.setComplianceRequirements("");  // 컴플라이언스는 별도 시스템으로 처리
            systemCtx.setSecurityPosture(systemContext != null && systemContext.getSecurityPosture() != null ?
                    systemContext.getSecurityPosture() : "STANDARD");

            String promptText = promptTemplate.buildPrompt(
                    event, layer1Decision, layer2Decision,
                    threatIntelCtx, historicalCtx, systemCtx
            );

            // UnifiedLLMOrchestrator를 사용한 execute + 수동 JSON 파싱
            // BeanOutputConverter 제거로 3200+ 토큰 → 700 토큰 (78% 감소!)
            // 예상 성능: 5-10초 → 1-3초 (3-10배 개선!)
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

                // AI Native: onErrorResume에서 규칙 기반 기본값 제거
                // riskScore/confidence를 null로 반환하여 NaN 처리
                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(timeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.warn("[Layer3][AI Native] LLM execution failed, applying failsafe blocking: {}", event.getEventId(), e);
                            return Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"BLOCK\",\"classification\":\"UNKNOWN\",\"scenario\":\"[AI Native] LLM execution failed - failsafe blocking applied\"}");
                        })
                        .block();

                response = parseJsonResponse(jsonResponse);
            } else {
                log.warn("UnifiedLLMOrchestrator not available for Layer 3 analysis");
                response = createDefaultResponse();
            }

            // 6. 응답을 SecurityDecision 으로 변환
            SecurityDecision expertDecision = convertToSecurityDecision(response, event, layer2Decision);

            // 7. SOAR 통합 및 실행
            if (enableSoar && expertDecision.getRiskScore() >= autoExecuteThreshold) {
//                executeSoarPlaybook(expertDecision, event);
            }

            // 9. 승인이 필요한 경우 처리
            if (expertDecision.isRequiresApproval() && approvalService != null) {
//                handleApprovalProcess(expertDecision, event);
            }

            // 10. 인시던트 생성 및 알림
//            createSecurityIncident(expertDecision, event);

            // 11. 벡터 스토어에 저장 (학습용)
            storeInVectorDatabase(event, expertDecision, response);

            // 11-1. 고위험 이벤트 시 Redis 메타데이터 업데이트
            if (expertDecision.getRiskScore() >= 0.8) {
                String sourceIp = event.getSourceIp();
                if (sourceIp != null && !sourceIp.isEmpty()) {
                    // 공격 카운트 증가 및 IP 평판 하향
                    incrementAttackCount(sourceIp);

                }

                // 자산 중요도 동적 업데이트
                String targetResource = event.getTargetResource() != null
                        ? event.getTargetResource()
                        : event.getEventType() != null ? event.getEventType().toString() : null;

                if (targetResource != null) {
                    String criticality = expertDecision.getRiskScore() >= 0.9 ? "CRITICAL" : "HIGH";
                    initializeAssetMetadata(targetResource, criticality);
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

    /**
     * 위협 인텔리전스 수집 (Vector-based)
     */
    private ThreatIntelligence gatherThreatIntelligence(SecurityEvent event) {
        ThreatIntelligence intel = new ThreatIntelligence();

        // Null safety: event가 null인 경우 기본값 반환
        if (event == null) {
            intel.setReputationScore(0.5);
            intel.setKnownActors(new ArrayList<>());
            intel.setRelatedCampaigns(new ArrayList<>());
            intel.setIocMatches(new ArrayList<>());
            intel.setGeoLocation("Unknown");
            return intel;
        }

        // IP 평판 조회 (null-safe)
        String sourceIp = event.getSourceIp();
        intel.setReputationScore(checkIpReputation(sourceIp));

        // 알려진 위협 액터 매칭 (Vector-based)
        List<String> knownActors = findKnownThreatActors(event);
        if (knownActors.isEmpty()) {
            knownActors.add("[NO_KNOWN_ACTORS: first time observation]");
        }
        intel.setKnownActors(knownActors);

        // 관련 캠페인 식별 (Vector-based)
        List<String> relatedCampaigns = identifyRelatedCampaigns(event);
        if (relatedCampaigns.isEmpty()) {
            relatedCampaigns.add("[NO_CAMPAIGNS: isolated incident or new pattern]");
        }
        intel.setRelatedCampaigns(relatedCampaigns);

        // IOC 매칭
        List<String> iocMatches = matchIndicatorsOfCompromise(event);
        if (iocMatches.isEmpty()) {
            iocMatches.add("[NO_IOC_MATCH: no indicators found]");
        }
        intel.setIocMatches(iocMatches);

        // 지리적 위치 분석 (null-safe)
        intel.setGeoLocation(getGeoLocation(sourceIp));

        return intel;
    }

    /**
     * SecurityEvent를 HCADContext로 변환 (Layer2와 동일한 로직)
     */
    private HCADContext convertToHCADContext(SecurityEvent event) {
        // Null safety: event가 null인 경우 기본 값으로 HCADContext 생성
        if (event == null) {
            return HCADContext.builder()
                    .userId("unknown")
                    .sessionId("unknown")
                    .requestPath("/unknown")
                    .httpMethod("GET")
                    .remoteIp("0.0.0.0")
                    .userAgent("unknown")
                    .timestamp(java.time.Instant.now())
                    .currentTrustScore(0.5)
                    .recentRequestCount(0)
                    .isNewSession(false)
                    .authenticationMethod("unknown")
                    .resourceType("general")
                    .build();
        }

        return HCADContext.builder()
                .userId(event.getUserId() != null ? event.getUserId() : "unknown")
                .sessionId(event.getSessionId() != null ? event.getSessionId() : "unknown")
                .requestPath(eventEnricher != null ?
                        eventEnricher.getTargetResource(event).orElse("/unknown") : "/unknown")
                .httpMethod(eventEnricher != null ?
                        eventEnricher.getHttpMethod(event).orElse("GET") : "GET")
                .remoteIp(event.getSourceIp() != null ? event.getSourceIp() : "0.0.0.0")
                .userAgent(event.getUserAgent() != null ? event.getUserAgent() : "unknown")
                .timestamp(event.getTimestamp() != null ?
                        event.getTimestamp().atZone(java.time.ZoneId.systemDefault()).toInstant() :
                        java.time.Instant.now())
                .currentTrustScore(event.getRiskScore() != null ? (1.0 - event.getRiskScore() / 10.0) : 0.5)
                .recentRequestCount(0)
                .isNewSession(false)
                .authenticationMethod("unknown")
                .resourceType(classifyResourceType(
                        eventEnricher != null ?
                                eventEnricher.getTargetResource(event).orElse("/unknown") : "/unknown"))
                .build();
    }

    /**
     * AI Native: 패턴 매칭 규칙 완전 제거
     * - contains("/admin"), "/api" 등 규칙 제거
     * - 경로를 그대로 반환하여 LLM이 리소스 유형 분류
     * - LLM이 경로 컨텍스트를 분석하여 직접 판단
     */
    private String classifyResourceType(String path) {
        // AI Native: 패턴 매칭 제거, raw 경로 그대로 반환
        return path;
    }

    /**
     * IP 평판 확인
     */
    private double checkIpReputation(String ip) {
        // Null safety: IP가 null인 경우 기본값 반환
        if (ip == null || ip.trim().isEmpty()) {
            return 0.5;
        }

        if (redisTemplate == null) {
            return 0.5;
        }

        try {
            String reputationKey = ZeroTrustRedisKeys.ipReputation(ip);
            Object reputation = redisTemplate.opsForValue().get(reputationKey);
            if (reputation != null) {
                return Double.parseDouble(reputation.toString());
            }

            // 기본 평판 점수 저장 (첫 조회 시)
            updateIpReputation(ip, 0.5);

        } catch (Exception e) {
            log.debug("Failed to check IP reputation for IP: {}", ip, e);
        }

        // 기본 평판 점수
        return 0.5;
    }

    /**
     * 알려진 위협 액터 찾기 (UnifiedVectorService RAG 기반)
     */
    private List<String> findKnownThreatActors(SecurityEvent event) {
        List<String> actors = new ArrayList<>();

        // 1. UnifiedVectorService를 통한 RAG 검색 (우선순위)
        if (unifiedVectorService != null) {
            try {
                String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
                String sourceIp = event.getSourceIp() != null ? event.getSourceIp() : "unknown";
                String attackVector = event.getAttackVector() != null ? event.getAttackVector() : "";

                String query = String.format("threat-actor %s %s IP:%s", eventType, attackVector, sourceIp);

                org.springframework.ai.vectorstore.SearchRequest searchRequest =
                    org.springframework.ai.vectorstore.SearchRequest.builder()
                        .query(query)
                        .topK(10)
                        .similarityThreshold(0.7)
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

        // 2. BehaviorVectorService fallback (기존 로직)
        if (actors.isEmpty() && behaviorVectorService != null) {
            try {
                String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
                String sourceIp = event.getSourceIp() != null ? event.getSourceIp() : "unknown";

                List<Document> similarThreats = behaviorVectorService.findSimilarBehaviors(
                        sourceIp,
                        "threat-actor " + eventType,
                        5
                );

                actors = similarThreats.stream()
                        .map(doc -> {
                            Map<String, Object> meta = doc.getMetadata();
                            String actor = meta.getOrDefault("threatActor", "UNKNOWN").toString();
                            double score = (double) meta.getOrDefault("similarityScore", 0.0);
                            return String.format("%s (confidence: %.2f)", actor, score);
                        })
                        .filter(actor -> !actor.contains("UNKNOWN"))
                        .limit(3)
                        .collect(Collectors.toList());
            } catch (Exception e) {
                log.warn("BehaviorVectorService threat actor search failed: {}", e.getMessage());
            }
        }

        // 3. Rule-based fallback
        if (actors.isEmpty()) {
            actors = findKnownThreatActorsFallback(event);
        }

        return actors;
    }

    /**
     * AI Native: 패턴 매칭 규칙 완전 제거
     * - contains("APT"), "Lazarus", "Emotet" 규칙 제거
     * - Vector 서비스 실패 시 빈 리스트 반환 (LLM이 직접 판단)
     * - LLM이 페이로드 컨텍스트를 분석하여 위협 액터 식별
     */
    private List<String> findKnownThreatActorsFallback(SecurityEvent event) {
        log.warn("[Layer3][AI Native] Vector service unavailable, threat actor detection delegated to LLM");
        return new ArrayList<>();
    }

    /**
     * 관련 캠페인 식별 (UnifiedVectorService RAG 기반)
     */
    private List<String> identifyRelatedCampaigns(SecurityEvent event) {
        List<String> campaigns = new ArrayList<>();

        // 1. UnifiedVectorService를 통한 RAG 검색 (우선순위)
        if (unifiedVectorService != null) {
            try {
                String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
                Optional<String> targetResource = eventEnricher.getTargetResource(event);
                String mitreId = event.getMitreAttackId() != null ? event.getMitreAttackId() : "";

                String campaignQuery = String.format("campaign %s targeting %s %s",
                        eventType, targetResource.orElse("unknown"), mitreId);

                org.springframework.ai.vectorstore.SearchRequest searchRequest =
                    org.springframework.ai.vectorstore.SearchRequest.builder()
                        .query(campaignQuery)
                        .topK(10)
                        .similarityThreshold(0.65)
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

        // 2. BehaviorVectorService fallback (기존 로직)
        if (campaigns.isEmpty() && behaviorVectorService != null) {
            try {
                String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
                Optional<String> targetResource = eventEnricher.getTargetResource(event);

                String campaignQuery = String.format("campaign %s targeting %s",
                        eventType,
                        targetResource.orElse("unknown"));

                List<Document> similarCampaigns = behaviorVectorService.findSimilarBehaviors(
                        event.getSourceIp(),
                        campaignQuery,
                        5
                );

                campaigns = similarCampaigns.stream()
                        .map(doc -> {
                            Map<String, Object> meta = doc.getMetadata();
                            String campaignId = meta.getOrDefault("campaignId", "UNKNOWN").toString();
                            String campaignName = meta.getOrDefault("campaignName", "").toString();
                            double similarity = (double) meta.getOrDefault("similarityScore", 0.0);

                            if (!campaignName.isEmpty()) {
                                return String.format("%s (%s, similarity: %.2f)", campaignName, campaignId, similarity);
                            } else {
                                return String.format("Campaign %s (similarity: %.2f)", campaignId, similarity);
                            }
                        })
                        .filter(c -> !c.contains("UNKNOWN"))
                        .limit(3)
                        .collect(Collectors.toList());
            } catch (Exception e) {
                log.warn("BehaviorVectorService campaign search failed: {}", e.getMessage());
            }
        }

        // 3. Fallback
        if (campaigns.isEmpty()) {
            campaigns = identifyRelatedCampaignsFallback(event);
        }

        return campaigns;
    }

    /**
     * Fallback: 관련 캠페인 식별
     */
    private List<String> identifyRelatedCampaignsFallback(SecurityEvent event) {
        return new ArrayList<>();  // Vector 서비스 없을 때는 빈 리스트 반환
    }

    /**
     * IOC 매칭
     */
    private List<String> matchIndicatorsOfCompromise(SecurityEvent event) {
        // 실제 위협 인텔리전스 서비스와 연동이 필요함
        // 현재는 빈 리스트 반환
        return new ArrayList<>();
    }

    /**
     * 지리적 위치 조회
     */
    private String getGeoLocation(String ip) {
        // IP가 null인 경우 처리
        if (ip == null || ip.trim().isEmpty()) {
            return "Unknown - Invalid IP";
        }

        // 실제로는 GeoIP 데이터베이스 사용
        // 여기서는 단순화
        if (ip.startsWith("10.") || ip.startsWith("192.168.")) {
            return "Internal Network";
        }
        return "External - Country Unknown";
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

        // 대상 취약점 이력
        List<String> vulnHistory = getTargetVulnerabilityHistory(event);
        if (vulnHistory.isEmpty()) {
            vulnHistory.add("[NO_VULNERABILITIES: clean history]");
        }
        context.setVulnerabilityHistory(vulnHistory);

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

    /**
     * Fallback: 유사 인시던트 찾기 (Redis key pattern)
     */
    private List<String> findSimilarIncidentsFallback(SecurityEvent event) {
        List<String> incidents = new ArrayList<>();

        // Null safety: event가 null이거나 eventType이 null인 경우 빈 리스트 반환
        if (event == null || event.getEventType() == null) {
            return incidents;
        }

        if (redisTemplate != null) {
            try {
                Set<String> keys = redisTemplate.keys("incident:*:" + event.getEventType());
                if (keys != null) {
                    incidents = keys.stream()
                            .limit(5)
                            .map(key -> {
                                String[] parts = key.split(":");
                                return parts.length > 1 ? parts[1] : key;
                            })
                            .collect(Collectors.toList());
                }
            } catch (Exception e) {
                log.debug("Failed to find similar incidents for event type: {}",
                        event.getEventType(), e);
            }
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

    /**
     * 대상 취약점 이력
     */
    private List<String> getTargetVulnerabilityHistory(SecurityEvent event) {
        List<String> vulnerabilities = new ArrayList<>();

        // Null safety: event가 null인 경우 빈 리스트 반환
        if (event == null) {
            return vulnerabilities;
        }

        // 실제로는 취약점 데이터베이스 조회
        // 여기서는 단순화
        if (eventEnricher != null) {
            Optional<String> target = eventEnricher.getTargetResource(event);
            if (target.isPresent()) {
                String targetStr = target.get();
                if (targetStr.contains("admin")) {
                    vulnerabilities.add("Previous privilege escalation attempts");
                }
                if (targetStr.contains("api")) {
                    vulnerabilities.add("API abuse history");
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 시스템 컨텍스트 평가
     */
    private SystemContext evaluateSystemContext(SecurityEvent event) {
        SystemContext context = new SystemContext();

        // Null safety: event가 null인 경우 기본값 설정
        if (event == null) {
            context.setAssetCriticality("MEDIUM");
            context.setDataSensitivity("INTERNAL");
            context.setSecurityPosture("STANDARD");
            return context;
        }

        // 자산 중요도
        String targetResource = (eventEnricher != null) ?
                eventEnricher.getTargetResource(event).orElse(null) : null;
        context.setAssetCriticality(determineAssetCriticality(targetResource));

        // 데이터 민감도
        context.setDataSensitivity(determineDataSensitivity(targetResource));

        // 현재 보안 상태
        context.setSecurityPosture(getCurrentSecurityPosture());

        return context;
    }

    /**
     * 자산 중요도 결정 (Metadata + Vector-based with fallback)
     */
    private String determineAssetCriticality(String target) {
        if (target == null) return "UNKNOWN";

        if (behaviorVectorService == null || redisTemplate == null) {
            return determineAssetCriticalityFallback(target);
        }

        try {
            String metadataKey = ZeroTrustRedisKeys.assetMetadata(target);
            Object metadata = redisTemplate.opsForValue().get(metadataKey);

            if (metadata != null && metadata instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> assetMeta = (Map<String, Object>) metadata;
                String criticality = (String) assetMeta.get("criticality");
                if (criticality != null) {
                    return criticality;
                }
            }

            String assetQuery = String.format("asset criticality for %s resource", target);
            List<Document> similarAssets = behaviorVectorService.findSimilarBehaviors(
                    "system",
                    assetQuery,
                    3
            );

            if (!similarAssets.isEmpty()) {
                Map<String, Object> meta = similarAssets.get(0).getMetadata();
                String vectorBasedCriticality = (String) meta.getOrDefault("assetCriticality", null);
                if (vectorBasedCriticality != null) {
                    return vectorBasedCriticality;
                }
            }

            return determineAssetCriticalityFallback(target);

        } catch (Exception e) {
            log.debug("Metadata/Vector-based asset criticality determination failed, using fallback", e);
            return determineAssetCriticalityFallback(target);
        }
    }

    /**
     * AI Native: 패턴 매칭 규칙 완전 제거
     * - contains("database"), "auth", "api", "admin" 등 규칙 제거
     * - Vector 서비스 실패 시 UNKNOWN 반환 (LLM이 직접 판단)
     * - LLM이 타겟 리소스 컨텍스트를 분석하여 자산 중요도 결정
     */
    private String determineAssetCriticalityFallback(String target) {
        log.warn("[Layer3][AI Native] Vector service unavailable, asset criticality delegated to LLM");
        return "UNKNOWN";
    }

    /**
     * AI Native: 패턴 매칭 규칙 완전 제거
     * - contains("personal"), "pii", "payment", "internal" 규칙 제거
     * - UNKNOWN 반환 (LLM이 직접 판단)
     * - LLM이 타겟 컨텍스트를 분석하여 데이터 민감도 결정
     */
    private String determineDataSensitivity(String target) {
        log.warn("[Layer3][AI Native] Data sensitivity determination delegated to LLM");
        return "UNKNOWN";
    }


    /**
     * 현재 보안 상태
     */
    private String getCurrentSecurityPosture() {
        // 실제로는 시스템 메트릭 조회
        return "NORMAL - No active threats detected";
    }

    /**
     * AI 응답 검증 및 수정
     *
     * AI Native: LLM 응답을 가공 없이 그대로 사용
     * - confidence/riskScore가 null이면 Double.NaN 사용 (규칙 기반 기본값 금지)
     * - LLM이 응답하지 않은 것은 "분석 불가" 상태로 명시
     */
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

        // classification 검증
        if (response.getClassification() == null || response.getClassification().equals("none")) {
            response.setClassification("UNKNOWN_THREAT");
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

    /**
     * 기본 Layer1 결정 생성
     *
     * AI Native: 기본값은 Double.NaN (LLM 분석 미수행 상태)
     * - Layer3에서 직접 호출 시 LLM 분석 결과가 없으므로 NaN
     */
    private SecurityDecision createDefaultLayer1Decision() {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ESCALATE)
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
                .processingTimeMs(50L)
                .build();
    }

    /**
     * 기본 Layer2 결정 생성
     *
     * AI Native: 기본값은 Double.NaN (LLM 분석 미수행 상태)
     * - Layer3에서 직접 호출 시 LLM 분석 결과가 없으므로 NaN
     */
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
     * Layer3SecurityResponse를 SecurityDecision으로 변환
     *
     * AI Native: LLM 응답을 가공 없이 그대로 변환
     * - null인 경우 Double.NaN 사용 (규칙 기반 기본값 금지)
     */
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

    /**
     * JSON 응답 파싱 (수동 파싱으로 BeanOutputConverter 제거)
     *
     * AI Native: LLM JSON 응답을 가공 없이 파싱
     * - 필드 미존재 시 Double.NaN 사용 (규칙 기반 기본값 금지)
     */
    private Layer3SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            String cleanedJson = extractJsonObject(jsonResponse);
            JsonNode jsonNode = objectMapper.readTree(cleanedJson);

            // AI Native: 필드 미존재 시 NaN (기본값 금지)
            Double riskScore = jsonNode.has("riskScore") ? jsonNode.get("riskScore").asDouble() : Double.NaN;
            Double confidence = jsonNode.has("confidence") ? jsonNode.get("confidence").asDouble() : Double.NaN;
            String action = jsonNode.has("action") ? jsonNode.get("action").asText() : "ESCALATE";
            String classification = jsonNode.has("classification") ? jsonNode.get("classification").asText() : "UNKNOWN";
            String scenario = jsonNode.has("scenario") ? jsonNode.get("scenario").asText() : "No scenario";
            String reasoning = jsonNode.has("reasoning") ? jsonNode.get("reasoning").asText() : "No reasoning";
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

    /**
     * JSON 객체 추출
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

        log.warn("No JSON object found in LLM response, using default: {}", text);
        return "{}";
    }

    /**
     * 기본 Layer3SecurityResponse 생성
     *
     * AI Native: LLM 분석 불가 시 기본 응답
     * - riskScore/confidence는 Double.NaN (규칙 기반 기본값 금지)
     * - LLM이 분석하지 않은 상태를 명시
     */
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
     * 문자열을 액션으로 매핑
     */
    private SecurityDecision.Action mapStringToAction(String action) {
        if (action == null) return SecurityDecision.Action.INVESTIGATE;
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

            // Redis로 인시던트 정보 저장하여 알림 처리

            // Redis에 저장
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

    /**
     * 안전 장치 결정 생성
     *
     * AI Native: LLM 분석 실패 시 안전 결정
     * - riskScore/confidence는 Double.NaN (규칙 기반 기본값 금지)
     * - 분석 실패 상태를 명시, BLOCK 액션은 안전 정책
     */
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

    // 내부 클래스들

    private static class ThreatIntelligence {
        private double reputationScore;
        private List<String> knownActors = new ArrayList<>();
        private List<String> relatedCampaigns = new ArrayList<>();
        private List<String> iocMatches = new ArrayList<>();
        private String geoLocation;

        // Getters and setters
        public double getReputationScore() { return reputationScore; }
        public void setReputationScore(double score) { this.reputationScore = score; }

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

    private static class SystemContext {
        private String assetCriticality;
        private String dataSensitivity;
        private List<String> complianceRequirements = new ArrayList<>();
        private String securityPosture;

        // Getters and setters
        public String getAssetCriticality() { return assetCriticality != null ? assetCriticality : "UNKNOWN"; }
        public void setAssetCriticality(String criticality) { this.assetCriticality = criticality; }

        public String getDataSensitivity() { return dataSensitivity != null ? dataSensitivity : "UNKNOWN"; }
        public void setDataSensitivity(String sensitivity) { this.dataSensitivity = sensitivity; }

        public List<String> getComplianceRequirements() { return complianceRequirements; }
        public void setComplianceRequirements(List<String> requirements) { this.complianceRequirements = requirements; }

        public String getSecurityPosture() { return securityPosture != null ? securityPosture : "UNKNOWN"; }
        public void setSecurityPosture(String posture) { this.securityPosture = posture; }
    }


    /**
     * Phase 3.1: Layer3 → Layer1 피드백 루프
     * Layer3의 전문가 분석 결과를 Layer1이 학습할 수 있도록 피드백
     */
    private void feedbackToLayer1(SecurityEvent event, SecurityDecision decision) {
        if (redisTemplate == null || decision.getRiskScore() < 0.7) {
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
            feedback.put("action", decision.getAction().toString());
            feedback.put("threatCategory", decision.getThreatCategory());
            feedback.put("mitreTactics", decision.getMitreMapping() != null ? new ArrayList<>(decision.getMitreMapping().keySet()) : List.of());
            feedback.put("iocIndicators", decision.getIocIndicators());
            feedback.put("timestamp", System.currentTimeMillis());

            storeFeedbackWithRetry(feedbackKey, feedback);

            String patternKey = localFeedbackProperties.getRedis().getPatternKeyPrefix() + event.getEventType();
            redisTemplate.opsForList().rightPush(patternKey, feedback);
            redisTemplate.expire(patternKey, Duration.ofDays(30));

            log.info("Layer3 → Layer1 Feedback stored: eventId={}, riskScore={}", event.getEventId(), decision.getRiskScore());

            if (layerFeedbackService != null) {
                double indexingThreshold = localFeedbackProperties.getRiskScore().getIndexingThreshold();
                double hotSyncThreshold = localFeedbackProperties.getRiskScore().getHotSyncThreshold();

                if (decision.getRiskScore() >= indexingThreshold) {
                    layerFeedbackService.indexLayer3Feedback(event, decision);
                }

                if (decision.getRiskScore() >= hotSyncThreshold) {
                    // AbstractTieredStrategy의 syncFeedbackToHotPath 사용
                    feedbackToHotPath(event, decision);
                }
            }

        } catch (Exception e) {
            log.warn("Failed to store Layer3 feedback", e);
        }
    }

    /**
     * Phase 7.3: 피드백 저장 with 재시도 로직
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

    @Override
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

    /**
     * AI Native: 규칙 기반 위험 점수 계산 제거
     * - LLM이 indicators를 분석하여 직접 riskScore를 반환해야 함
     * - 이 메서드는 LLM 분석 미수행 상태를 반환
     */
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        // AI Native: LLM이 직접 분석해야 함, 규칙 기반 계산 금지
        log.warn("[Layer3][AI Native] calculateRiskScore called without LLM - returning NaN");
        return Double.NaN;
    }

    // AI Native: mapRiskScoreToThreatLevel() 규칙 기반 매핑 완전 제거
    // LLM이 threatLevel을 직접 결정해야 함

    private String mapActionToRecommendation(SecurityDecision.Action action) {
        switch (action) {
            case BLOCK:
                return "BLOCK_WITH_INCIDENT_RESPONSE";
            case MITIGATE:
                return "APPLY_ADVANCED_MITIGATION";
            case INVESTIGATE:
                return "DEEP_FORENSIC_INVESTIGATION";
            case ESCALATE:
                return "ESCALATE_TO_SOC";
            default:
                return "EXPERT_REVIEW_REQUIRED";
        }
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

            // Layer3 전문가 분석 결과
            metadata.put("classification", response.getClassification() != null ? response.getClassification() : "UNKNOWN");
            if (response.getTactics() != null && !response.getTactics().isEmpty()) {
                metadata.put("tactics", String.join(",", response.getTactics()));
            }
            if (response.getTechniques() != null && !response.getTechniques().isEmpty()) {
                metadata.put("techniques", String.join(",", response.getTechniques()));
            }
            if (response.getIocIndicators() != null && !response.getIocIndicators().isEmpty()) {
                metadata.put("iocIndicators", String.join(",", response.getIocIndicators()));
            }

            // Layer3 ThreatIntelligence용 (실제 전문가 분석 기반)
            if (decision.getRiskScore() >= 0.8) {
                // 고위험: 전문가 분석 결과 활용
                metadata.put("threatActor", response.getClassification() != null ? response.getClassification() : "EXPERT-DETECTED");
                metadata.put("campaignId", "LAYER3-" + UUID.randomUUID().toString().substring(0, 8));
                metadata.put("campaignName", "Expert Analysis - " + (response.getClassification() != null ? response.getClassification() : "Unknown"));
                metadata.put("incidentId", "INC-L3-" + UUID.randomUUID().toString().substring(0, 8));
                metadata.put("mitreTactic", response.getTactics() != null && !response.getTactics().isEmpty() ? response.getTactics().get(0) : "TA0043-Reconnaissance");
                metadata.put("assetCriticality", "CRITICAL");
            } else {
                metadata.put("threatActor", "NONE");
                metadata.put("campaignId", "NONE");
                metadata.put("campaignName", "");
                metadata.put("incidentId", "");
                metadata.put("mitreTactic", "");
                metadata.put("assetCriticality", "MEDIUM");
            }

            // IOC 지표
            metadata.put("iocIndicator", response.getIocIndicators() != null && !response.getIocIndicators().isEmpty()
                    ? String.join(",", response.getIocIndicators())
                    : "");

            Document document = new Document(content, metadata);
            unifiedVectorService.storeDocument(document);

            // Phase 1: 고위험 이벤트는 별도로 threat 문서 저장 (Layer3 전문가 분석)
            if (decision.getRiskScore() >= 0.8) {
                storeThreatDocument(event, decision, response, content);
            }

        } catch (Exception e) {
            log.debug("Failed to store in vector database", e);
        }
    }

    /**
     * Phase 1: 위협 패턴 전용 문서 저장 (Layer3 전문가 분석)
     *
     * riskScore >= 0.8인 경우 threat 문서로 별도 저장
     * Layer3는 가장 심층적인 전문가 분석 결과를 포함
     */
    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, Layer3SecurityResponse response, String analysisContent) {
        try {
            Map<String, Object> threatMetadata = new HashMap<>();

            // 위협 전용 documentType (Enum 사용)
            threatMetadata.put("documentType", VectorDocumentType.THREAT.getValue());
            threatMetadata.put("threatConfirmed", true); // Layer3 도달 = 확정 위협
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
            threatMetadata.put("threatType", determineThreatType(response));
            threatMetadata.put("threatCategory", decision.getThreatCategory() != null ? decision.getThreatCategory() : response.getClassification());
            threatMetadata.put("riskCategory", decision.getRiskScore() >= 0.95 ? "CRITICAL" : "HIGH");

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

            // MITRE ATT&CK (전문가 분석 결과 우선)
            String mitreTactic = response.getTactics() != null && !response.getTactics().isEmpty() ?
                    response.getTactics().get(0) : "TA0043:Reconnaissance";
            threatMetadata.put("mitreTactic", mitreTactic);
            threatMetadata.put("patternType", "expert_confirmed");

            // Layer 정보
            threatMetadata.put("processingLayer", "Layer3");
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

    /**
     * Layer3SecurityResponse 기반 위협 유형 분류 (전문가 분석)
     *
     * AI Native: LLM이 반환한 classification을 그대로 사용
     * - 패턴 매칭 규칙 완전 제거
     * - LLM이 분류한 값을 신뢰
     */
    private String determineThreatType(Layer3SecurityResponse response) {
        // AI Native: LLM이 반환한 classification 그대로 사용
        if (response.getClassification() != null && !response.getClassification().isEmpty()) {
            return response.getClassification();
        }

        // AI Native: LLM이 classification을 반환하지 않은 경우만 null
        return null;
    }

    /**
     * IP Reputation 업데이트
     * 위협 이벤트 발생 시 IP 평판 점수 하향 조정
     */
    private void updateIpReputation(String ip, double score) {
        if (redisTemplate == null || ip == null || ip.isEmpty()) {
            return;
        }

        try {
            String reputationKey = ZeroTrustRedisKeys.ipReputation(ip);
            redisTemplate.opsForValue().set(reputationKey, score, Duration.ofDays(30));
            log.debug("Updated IP reputation: ip={}, score={}", ip, score);
        } catch (Exception e) {
            log.debug("Failed to update IP reputation: ip={}", ip, e);
        }
    }

    /**
     * 공격 카운트 증가
     * 고위험 이벤트 탐지 시 호출
     *
     * AI Native: 카운트만 증가, 규칙 기반 평판 계산 제거
     * - IP 평판은 LLM이 컨텍스트로 받아서 직접 판단
     */
    private void incrementAttackCount(String sourceIp) {
        if (redisTemplate == null || sourceIp == null || sourceIp.isEmpty()) {
            return;
        }

        try {
            String attackCountKey = ZeroTrustRedisKeys.attackCount(sourceIp);
            Long count = redisTemplate.opsForValue().increment(attackCountKey);
            redisTemplate.expire(attackCountKey, Duration.ofDays(7));
            log.debug("Incremented attack count: ip={}, count={}", sourceIp, count);

            // AI Native: 규칙 기반 평판 계산 제거
            // LLM이 attackCount를 컨텍스트로 받아서 직접 판단
        } catch (Exception e) {
            log.debug("Failed to increment attack count: ip={}", sourceIp, e);
        }
    }

    /**
     * 자산 중요도 초기화
     * 시스템 초기화 시 또는 동적으로 자산 메타데이터 생성
     */
    private void initializeAssetMetadata(String resource, String criticality) {
        if (redisTemplate == null || resource == null || resource.isEmpty()) {
            return;
        }

        try {
            String metadataKey = ZeroTrustRedisKeys.assetMetadata(resource);
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("criticality", criticality);
            metadata.put("lastUpdated", LocalDateTime.now().toString());
            metadata.put("resourceType", determineResourceType(resource));

            redisTemplate.opsForValue().set(metadataKey, metadata, Duration.ofDays(30));
            log.debug("Initialized asset metadata: resource={}, criticality={}", resource, criticality);
        } catch (Exception e) {
            log.debug("Failed to initialize asset metadata: resource={}", resource, e);
        }
    }

    /**
     * AI Native: 패턴 매칭 규칙 완전 제거
     * - contains("admin"), "api", "database", "payment" 등 규칙 제거
     * - 리소스를 그대로 반환하여 LLM이 리소스 유형 판별
     * - LLM이 리소스 컨텍스트를 분석하여 직접 판단
     */
    private String determineResourceType(String resource) {
        // AI Native: 패턴 매칭 제거, raw 리소스 그대로 반환
        return resource != null ? resource : "UNKNOWN";
    }

}