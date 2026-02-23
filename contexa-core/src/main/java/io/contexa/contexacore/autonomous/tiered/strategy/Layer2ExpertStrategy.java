package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.soar.approval.ApprovalRequestDetails;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

@Slf4j
public class Layer2ExpertStrategy extends AbstractTieredStrategy {

    private final ApprovalService approvalService;
    private final SecurityLearningService securityLearningService;

    @Autowired
    public Layer2ExpertStrategy(UnifiedLLMOrchestrator llmOrchestrator,
                                ApprovalService approvalService,
                                RedisTemplate<String, Object> redisTemplate,
                                SecurityEventEnricher eventEnricher,
                                SecurityPromptTemplate promptTemplate,
                                UnifiedVectorService unifiedVectorService,
                                BehaviorVectorService behaviorVectorService,
                                BaselineLearningService baselineLearningService,
                                TieredStrategyProperties tieredStrategyProperties,
                                SecurityLearningService securityLearningService) {
        super(llmOrchestrator, redisTemplate, eventEnricher, promptTemplate,
              behaviorVectorService, unifiedVectorService, baselineLearningService,
              tieredStrategyProperties);

        this.approvalService = approvalService;
        this.securityLearningService = securityLearningService;
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        SecurityDecision expertDecision = performDeepAnalysis(event);
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

    public SecurityDecision performDeepAnalysis(SecurityEvent event) {
        if (event == null) {
            log.error("[Layer2] Analysis failed: event is null");
            return createFailsafeDecision(null, System.currentTimeMillis());
        }

        long startTime = System.currentTimeMillis();
        try {
            List<Document> relatedDocuments = getCachedOrSearchRelatedContext(event);
            SecurityPromptTemplate.SessionContext sessionCtx = getCachedOrBuildSessionContext(event);
            SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = getCachedOrBuildBehaviorAnalysis(event, relatedDocuments);
            String promptText = promptTemplate.buildPrompt(event, sessionCtx, behaviorCtx, relatedDocuments);

            SecurityResponse response;
            if (llmOrchestrator != null) {
                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(promptText))
                        .tier(2)
                        .securityTaskType(ExecutionContext.SecurityTaskType.EXPERT_INVESTIGATION)
                        .timeoutMs((int) tieredStrategyProperties.getLayer2().getTimeoutMs())
                        .requestId(event.getEventId())
                        .userId(event.getUserId())
                        .sessionId(event.getSessionId())
                        .temperature(0.0)
                        .topP(1.0)
                        .build();

                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(tieredStrategyProperties.getLayer2().getTimeoutMs()))
                        .onErrorResume(Exception.class, e -> {
                            log.error("[Layer2] LLM execution failed, applying failsafe blocking: {}", event.getEventId(), e);
                            return Mono.just("{\"riskScore\":0.9,\"confidence\":0.3,\"action\":\"BLOCK\",\"reasoning\":\"LLM execution failed - failsafe blocking applied\",\"threatCategory\":\"UNKNOWN\"}");
                        })
                        .block();

                response = parseJsonResponse(jsonResponse);
            } else {
                log.error("[Layer2] UnifiedLLMOrchestrator not available");
                response = createDefaultResponse();
            }

            SecurityDecision expertDecision = convertToSecurityDecision(response, event);

            if (expertDecision.getAction() == ZeroTrustAction.BLOCK
                    || expertDecision.getAction() == ZeroTrustAction.CHALLENGE) {
                triggerPolicyEvolution(event, expertDecision,
                        buildAnalysisContext(sessionCtx, behaviorCtx, relatedDocuments));
            }

            if (tieredStrategyProperties.getLayer2().isEnableSoar() && expertDecision.getAction() == ZeroTrustAction.BLOCK) {
                executeSoarPlaybook(expertDecision, event);
            }

            if (expertDecision.isRequiresApproval() && approvalService != null) {
                handleApprovalProcess(expertDecision, event);
            }

            if (securityLearningService != null) {
                securityLearningService.postProcessDecision(event, expertDecision);
            }

            expertDecision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            expertDecision.setProcessingLayer(2);

            return expertDecision;

        } catch (Exception e) {
            log.error("[Layer2] Expert analysis failed for event {}", event.getEventId() != null ? event.getEventId() : "unknown", e);
            return createFailsafeDecision(event, startTime);
        }
    }

    public Mono<SecurityDecision> performDeepAnalysisAsync(SecurityEvent event) {
        return Mono.fromCallable(() -> performDeepAnalysis(event))
                .timeout(Duration.ofMillis(tieredStrategyProperties.getLayer2().getTimeoutMs()))
                .onErrorResume(throwable -> {
                    log.error("[Layer2] Async analysis failed or timed out", throwable);
                    return Mono.just(createFailsafeDecision(event, System.currentTimeMillis()));
                });
    }

    private List<Document> searchRelatedContext(SecurityEvent event) {
        double similarityThreshold = tieredStrategyProperties.getLayer2().getRag().getSimilarityThreshold();
        return searchRelatedContextBase(event, tieredStrategyProperties.getLayer2().getRagTopK(), similarityThreshold);
    }

    private SecurityPromptTemplate.SessionContext getCachedOrBuildSessionContext(SecurityEvent event) {
        SecurityPromptTemplate.SessionContext cached = getCachedSessionContext(event.getEventId());
        if (cached != null) {
            return cached;
        }
        log.error("[Layer2] Session context cache miss for event {}, rebuilding from event data", event.getEventId());
        return rebuildSessionContext(event);
    }

    private SecurityPromptTemplate.BehaviorAnalysis getCachedOrBuildBehaviorAnalysis(
            SecurityEvent event, List<Document> ragDocuments) {
        SecurityPromptTemplate.BehaviorAnalysis cached = getCachedBehaviorAnalysis(event.getEventId());
        if (cached != null) {
            return cached;
        }
        log.error("[Layer2] Behavior analysis cache miss for event {}, rebuilding from event data", event.getEventId());
        return rebuildBehaviorAnalysis(event, ragDocuments);
    }

    private SecurityPromptTemplate.SessionContext rebuildSessionContext(SecurityEvent event) {
        SecurityPromptTemplate.SessionContext ctx = new SecurityPromptTemplate.SessionContext();
        ctx.setSessionId(event.getSessionId());
        ctx.setUserId(event.getUserId());

        if (event.getMetadata() != null) {
            Object authMethod = event.getMetadata().get("authMethod");
            if (authMethod instanceof String authMethodStr) {
                ctx.setAuthMethod(authMethodStr);
            }
        }

        return ctx;
    }

    private SecurityPromptTemplate.BehaviorAnalysis rebuildBehaviorAnalysis(
            SecurityEvent event, List<Document> ragDocuments) {
        List<String> similarEvents = extractSimilarEventsSummary(ragDocuments);
        BaseBehaviorAnalysis base = analyzeBehaviorPatternsBase(event, baselineLearningService, similarEvents);

        SecurityPromptTemplate.BehaviorAnalysis ctx = new SecurityPromptTemplate.BehaviorAnalysis();
        ctx.setSimilarEvents(base.getSimilarEvents());
        ctx.setBaselineContext(base.getBaselineContext());
        ctx.setBaselineEstablished(base.isBaselineEstablished());

        if (event.getUserAgent() != null) {
            ctx.setCurrentUserAgentOS(SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent()));
            ctx.setCurrentUserAgentBrowser(SecurityEventEnricher.extractBrowserSignature(event.getUserAgent()));
        }

        if (event.getUserId() != null && baselineLearningService != null) {
            try {
                BaselineVector baseline = baselineLearningService.getBaseline(event.getUserId());
                if (baseline != null) {
                    ctx.setBaselineUpdateCount(baseline.getUpdateCount());
                    ctx.setBaselineAvgTrustScore(baseline.getAvgTrustScore());
                    ctx.setBaselineIpRanges(baseline.getNormalIpRanges());
                    ctx.setBaselineOperatingSystems(baseline.getNormalOperatingSystems());
                    ctx.setBaselineUserAgents(baseline.getNormalUserAgents());
                    ctx.setBaselineFrequentPaths(baseline.getFrequentPaths());
                    ctx.setBaselineAccessHours(baseline.getNormalAccessHours());
                    if (baseline.getNormalUserAgents() != null && baseline.getNormalUserAgents().length > 0) {
                        ctx.setPreviousUserAgentBrowser(baseline.getNormalUserAgents()[0]);
                    }
                }
            } catch (Exception e) {
                log.error("[Layer2] Failed to load baseline for user {}: {}", event.getUserId(), e.getMessage());
            }
        }

        return ctx;
    }

    private List<Document> getCachedOrSearchRelatedContext(SecurityEvent event) {
        List<Document> cached = getCachedRagDocuments(event.getEventId());
        if (cached != null) {
            return cached;
        }
        return searchRelatedContext(event);
    }

    private SecurityDecision convertToSecurityDecision(SecurityResponse response, SecurityEvent event) {
        SecurityDecision decision = convertToSecurityDecisionBase(response, event);
        decision.setProcessingLayer(2);
        decision.setLlmModel("tier-2-auto-selected");
        if (response != null && response.getMitre() != null && !response.getMitre().isEmpty()) {
            Map<String, String> mitreMapping = new HashMap<>();
            mitreMapping.put(response.getMitre(), response.getMitre());
            decision.setMitreMapping(mitreMapping);
        }
        return decision;
    }

    private void executeSoarPlaybook(SecurityDecision decision, SecurityEvent event) {
        if (!tieredStrategyProperties.getLayer2().isEnableSoar() || decision.getSoarPlaybook() == null) {
            return;
        }
        try {
            List<Map<String, Object>> actions = new ArrayList<>();

            if (decision.getAction() == ZeroTrustAction.BLOCK) {
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
            log.error("[Layer2] Failed to execute SOAR playbook", e);
        }
    }

    private void handleApprovalProcess(SecurityDecision decision, SecurityEvent event) {
        if (approvalService == null) {
            log.error("[Layer2] Approval service not available");
            return;
        }
        try {
            SoarContext soarContext = new SoarContext();
            soarContext.setSessionId(event.getSessionId());
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
            approvalService.requestApproval(soarContext, details);
        } catch (Exception e) {
            log.error("[Layer2] Failed to request approval", e);
        }
    }

    private SecurityDecision createFailsafeDecision(SecurityEvent event, long startTime) {
        return SecurityDecision.builder()
                .action(ZeroTrustAction.BLOCK)
                .riskScore(0.9)
                .confidence(0.3)
                .analysisTime(startTime)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .processingLayer(2)
                .eventId(event != null ? event.getEventId() : "unknown")
                .reasoning("[AI Native] Layer 2 LLM analysis failed - applying failsafe blocking")
                .requiresApproval(true)
                .expertRecommendation("Manual review required - LLM analysis failed")
                .build();
    }

    @Override
    protected String getLayerName() {
        return "Layer2";
    }

    @Override
    public String getStrategyName() {
        return "Layer2-Expert-Strategy";
    }

    private String mapActionToRecommendation(ZeroTrustAction action) {
        return switch (action) {
            case ALLOW -> "ALLOW_WITH_MONITORING";
            case BLOCK -> "BLOCK_WITH_INCIDENT_RESPONSE";
            case CHALLENGE -> "REQUIRE_REAUTHENTICATION";
            case ESCALATE, PENDING_ANALYSIS -> "ESCALATE_TO_SOC";
        };
    }
}
