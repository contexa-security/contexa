/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityResponse;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditForwardingService;
import io.contexa.contexacore.autonomous.saas.SaasBaselineSeedService;
import io.contexa.contexacore.autonomous.saas.SaasDetectionStrategyPackService;
import io.contexa.contexacore.autonomous.saas.SaasThreatIntelligenceService;
import io.contexa.contexacore.autonomous.saas.SaasThreatKnowledgePackService;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.soar.approval.ApprovalRequestDetails;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class Layer2ExpertStrategy extends AbstractTieredStrategy {

    private final ApprovalService approvalService;
    private final SecurityContextDataStore dataStore;
    private final SecurityLearningService securityLearningService;
    private final SaasBaselineSeedService baselineSeedService;
    private final SaasThreatIntelligenceService threatIntelligenceService;
    private final SaasThreatKnowledgePackService threatKnowledgePackService;
    private final SaasDetectionStrategyPackService detectionStrategyPackService;
    private final PipelineOrchestrator pipelineOrchestrator;

    @Autowired
    public Layer2ExpertStrategy(ApprovalService approvalService,
                                SecurityContextDataStore dataStore,
                                SecurityEventEnricher eventEnricher,
                                SecurityDecisionStandardPromptTemplate promptTemplate,
                                UnifiedVectorService unifiedVectorService,
                                BehaviorVectorService behaviorVectorService,
                                BaselineLearningService baselineLearningService,
                                TieredStrategyProperties tieredStrategyProperties,
                                SecurityLearningService securityLearningService,
                                SaasBaselineSeedService baselineSeedService,
                                SaasThreatIntelligenceService threatIntelligenceService,
                                SaasThreatKnowledgePackService threatKnowledgePackService,
                                PromptContextAuthorizationService promptContextAuthorizationService,
                                PromptContextAuditForwardingService promptContextAuditForwardingService,
                                PipelineOrchestrator pipelineOrchestrator) {
        this(
                approvalService,
                dataStore,
                eventEnricher,
                promptTemplate,
                unifiedVectorService,
                behaviorVectorService,
                baselineLearningService,
                tieredStrategyProperties,
                securityLearningService,
                baselineSeedService,
                threatIntelligenceService,
                threatKnowledgePackService,
                null,
                promptContextAuthorizationService,
                promptContextAuditForwardingService,
                pipelineOrchestrator);
    }

    public Layer2ExpertStrategy(ApprovalService approvalService,
                                SecurityContextDataStore dataStore,
                                SecurityEventEnricher eventEnricher,
                                SecurityDecisionStandardPromptTemplate promptTemplate,
                                UnifiedVectorService unifiedVectorService,
                                BehaviorVectorService behaviorVectorService,
                                BaselineLearningService baselineLearningService,
                                TieredStrategyProperties tieredStrategyProperties,
                                SecurityLearningService securityLearningService,
                                SaasBaselineSeedService baselineSeedService,
                                SaasThreatIntelligenceService threatIntelligenceService,
                                SaasThreatKnowledgePackService threatKnowledgePackService,
                                SaasDetectionStrategyPackService detectionStrategyPackService,
                                PromptContextAuthorizationService promptContextAuthorizationService,
                                PromptContextAuditForwardingService promptContextAuditForwardingService,
                                PipelineOrchestrator pipelineOrchestrator) {
        this(
                approvalService,
                dataStore,
                eventEnricher,
                promptTemplate,
                unifiedVectorService,
                behaviorVectorService,
                baselineLearningService,
                tieredStrategyProperties,
                securityLearningService,
                baselineSeedService,
                threatIntelligenceService,
                threatKnowledgePackService,
                detectionStrategyPackService,
                promptContextAuthorizationService,
                promptContextAuditForwardingService,
                pipelineOrchestrator,
                null);
    }

    public Layer2ExpertStrategy(ApprovalService approvalService,
                                SecurityContextDataStore dataStore,
                                SecurityEventEnricher eventEnricher,
                                SecurityDecisionStandardPromptTemplate promptTemplate,
                                UnifiedVectorService unifiedVectorService,
                                BehaviorVectorService behaviorVectorService,
                                BaselineLearningService baselineLearningService,
                                TieredStrategyProperties tieredStrategyProperties,
                                SecurityLearningService securityLearningService,
                                SaasBaselineSeedService baselineSeedService,
                                SaasThreatIntelligenceService threatIntelligenceService,
                                SaasThreatKnowledgePackService threatKnowledgePackService,
                                SaasDetectionStrategyPackService detectionStrategyPackService,
                                PromptContextAuthorizationService promptContextAuthorizationService,
                                PromptContextAuditForwardingService promptContextAuditForwardingService,
                                PipelineOrchestrator pipelineOrchestrator,
                                StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry) {
        super(eventEnricher, promptTemplate,
              behaviorVectorService, unifiedVectorService, baselineLearningService,
              promptContextAuthorizationService, promptContextAuditForwardingService, tieredStrategyProperties,
              structuredOutputCapabilityRegistry);

        this.approvalService = approvalService;
        this.dataStore = dataStore;
        this.securityLearningService = securityLearningService;
        this.baselineSeedService = baselineSeedService;
        this.threatIntelligenceService = threatIntelligenceService;
        this.threatKnowledgePackService = threatKnowledgePackService;
        this.detectionStrategyPackService = detectionStrategyPackService;
        this.pipelineOrchestrator = pipelineOrchestrator;
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        SecurityDecision expertDecision = performDeepAnalysis(event);
        ZeroTrustAction autonomousAction = expertDecision.resolveAutonomousAction();
        String action = expertDecision.getAction() != null ? expertDecision.getAction().name() : null;

        return ThreatAssessment.builder()
                .riskScore(null)
                .confidence(expertDecision.getConfidence())
                .llmAuditRiskScore(expertDecision.resolveAuditRiskScore())
                .llmAuditConfidence(expertDecision.resolveAuditConfidence())
                .indicators(new ArrayList<>())
                .recommendedActions(List.of(mapActionToRecommendation(autonomousAction)))
                .strategyName("Layer2-Expert")
                .assessedAt(LocalDateTime.now())
                .shouldEscalate(false)
                .action(action)
                .autonomousAction(autonomousAction != null ? autonomousAction.name() : null)
                .llmDecisionPresent(expertDecision.getLlmDecisionPresent())
                .technicalFallbackApplied(expertDecision.getTechnicalFallbackApplied())
                .technicalFallbackCategory(expertDecision.getTechnicalFallbackCategory())
                .technicalFallbackReason(expertDecision.getTechnicalFallbackReason())
                .technicalFallbackAction(expertDecision.getTechnicalFallbackAction())
                .reasoning(expertDecision.getReasoning())
                .autonomyConstraintApplied(expertDecision.getAutonomyConstraintApplied())
                .autonomyConstraintReasons(expertDecision.getAutonomyConstraintReasons())
                .autonomyConstraintSummary(expertDecision.getAutonomyConstraintSummary())
                .build();
    }

    public SecurityDecision performDeepAnalysis(SecurityEvent event) {
        if (event == null) {
            log.error("[Layer2] Analysis failed: event is null");
            return createFailsafeDecision(null, System.currentTimeMillis(), "NULL_EVENT");
        }

        long startTime = System.currentTimeMillis();
        try {
            List<Document> relatedDocuments = getCachedOrSearchRelatedContext(event);
            SecurityDecisionStandardPromptTemplate.SessionContext sessionCtx = getCachedOrBuildSessionContext(event);
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorCtx = getCachedOrBuildBehaviorAnalysis(event, relatedDocuments);
            annotateThreatKnowledgeContext(event, behaviorCtx);

            SecurityResponse response;
            clearPromptRuntimeTelemetry(event);
            if (pipelineOrchestrator != null) {
                SecurityDecisionResponse pipelineResponse = executeSecurityDecisionPipeline(
                                pipelineOrchestrator,
                                event,
                                sessionCtx,
                                behaviorCtx,
                                relatedDocuments)
                        .timeout(Duration.ofMillis(tieredStrategyProperties.getLayer2().getTimeoutMs()))
                        .block();
                if (pipelineResponse == null) {
                    throw new IllegalStateException("Layer2 structured security decision pipeline returned null");
                }
                response = validateAndFixResponse(pipelineResponse.toSecurityResponse());
                capturePromptRuntimeTelemetry(event, pipelineResponse);
            } else {
                throw new IllegalStateException("Layer2 PipelineOrchestrator not available");
            }

            SecurityDecision expertDecision = convertToSecurityDecision(response, event);
            expertDecision.setLlmDecisionPresent(true);
            expertDecision.setTechnicalFallbackApplied(false);

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
            return createFailsafeDecision(event, startTime, resolveTechnicalFailureCategory(e));
        }
    }

    public Mono<SecurityDecision> performDeepAnalysisAsync(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        return Mono.fromCallable(() -> performDeepAnalysis(event))
                .timeout(Duration.ofMillis(tieredStrategyProperties.getLayer2().getTimeoutMs()))
                .onErrorResume(throwable -> {
                    log.error("[Layer2] Async analysis failed or timed out", throwable);
                    return Mono.just(createFailsafeDecision(event, startTime, resolveTechnicalFailureCategory(throwable)));
                });
    }

    private List<Document> searchRelatedContext(SecurityEvent event) {
        double similarityThreshold = tieredStrategyProperties.getLayer2().getRag().getSimilarityThreshold();
        return searchRelatedContextBase(event, tieredStrategyProperties.getLayer2().getRagTopK(), similarityThreshold);
    }

    private SecurityDecisionStandardPromptTemplate.SessionContext getCachedOrBuildSessionContext(SecurityEvent event) {
        SecurityDecisionStandardPromptTemplate.SessionContext cached = getCachedSessionContext(event.getEventId());
        if (cached != null) {
            return cached;
        }
        log.error("[Layer2] Session context cache miss for event {}, rebuilding from event data", event.getEventId());
        return rebuildSessionContext(event);
    }

    private SecurityDecisionStandardPromptTemplate.BehaviorAnalysis getCachedOrBuildBehaviorAnalysis(
            SecurityEvent event, List<Document> ragDocuments) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis cached = getCachedBehaviorAnalysis(event.getEventId());
        if (cached != null) {
            return cached;
        }
        log.error("[Layer2] Behavior analysis cache miss for event {}, rebuilding from event data", event.getEventId());
        return rebuildBehaviorAnalysis(event, ragDocuments);
    }

    private SecurityDecisionStandardPromptTemplate.SessionContext rebuildSessionContext(SecurityEvent event) {
        SecurityDecisionStandardPromptTemplate.SessionContext ctx = new SecurityDecisionStandardPromptTemplate.SessionContext();
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

    private SecurityDecisionStandardPromptTemplate.BehaviorAnalysis rebuildBehaviorAnalysis(
            SecurityEvent event, List<Document> ragDocuments) {
        List<String> similarEvents = extractSimilarEventsSummary(ragDocuments);
        BaseBehaviorAnalysis base = analyzeBehaviorPatternsBase(event, baselineLearningService, similarEvents);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis ctx = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        ctx.setBaselineEstablished(base.isBaselineEstablished());

        enrichBehaviorAnalysisWithRuntimeLearningSupport(
                ctx,
                event,
                baselineSeedService,
                threatIntelligenceService,
                threatKnowledgePackService,
                detectionStrategyPackService);

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
                            "event", event.getEventId()
                    )
            );
            actions.add(notifyAction);

            if (dataStore != null) {
                dataStore.storeSoarExecution(event.getEventId(), actions);
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
            soarContext.setOrganizationId(resolveOrganizationId(event));
            soarContext.setCreatedAt(LocalDateTime.now());

            Map<String, Object> metadata = Map.of(
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

    String resolveOrganizationId(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return "unresolved:unknown";
        }
        Object organizationId = firstPresentMetadata(
                event.getMetadata(),
                "organizationId",
                "orgId",
                "organization");
        if (organizationId instanceof String value && !value.isBlank()) {
            return value.trim();
        }
        String eventId = event.getEventId();
        if (eventId != null && !eventId.isBlank()) {
            return "unresolved:event:" + eventId.trim();
        }
        String userId = event.getUserId();
        if (userId != null && !userId.isBlank()) {
            return "unresolved:user:" + userId.trim();
        }
        return "unresolved:unknown";
    }

    private Object firstPresentMetadata(Map<String, Object> metadata, String... keys) {
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private SecurityDecision createFailsafeDecision(SecurityEvent event, long startTime, String fallbackCategory) {
        return createTechnicalFallbackDecision(
                event,
                ZeroTrustAction.BLOCK,
                "[AI Native] Layer 2 analysis failed - applying failsafe blocking",
                fallbackCategory,
                startTime,
                2,
                true,
                "Manual review required - LLM analysis failed");
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
