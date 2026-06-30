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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityResponse;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.context.policy.PromptRelevantRequestPathPolicy;
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
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Slf4j
public class Layer1ContextualStrategy extends AbstractTieredStrategy {

    private final SecurityContextDataStore dataStore;
    private final SecurityLearningService securityLearningService;
    private final SaasBaselineSeedService baselineSeedService;
    private final SaasThreatIntelligenceService threatIntelligenceService;
    private final SaasThreatKnowledgePackService threatKnowledgePackService;
    private final SaasDetectionStrategyPackService detectionStrategyPackService;
    private final PipelineOrchestrator pipelineOrchestrator;
    private final ExecutorService ragRetrievalExecutor;
    private final Cache<String, SessionContext> sessionContextCache;

    public Layer1ContextualStrategy(UnifiedVectorService unifiedVectorService,
                                    SecurityContextDataStore dataStore,
                                    SecurityEventEnricher eventEnricher,
                                    SecurityDecisionStandardPromptTemplate promptTemplate,
                                    BehaviorVectorService behaviorVectorService,
                                    BaselineLearningService baselineLearningService,
                                    SecurityLearningService securityLearningService,
                                    SaasBaselineSeedService baselineSeedService,
                                    SaasThreatIntelligenceService threatIntelligenceService,
                                    SaasThreatKnowledgePackService threatKnowledgePackService,
                                    PromptContextAuthorizationService promptContextAuthorizationService,
                                    PromptContextAuditForwardingService promptContextAuditForwardingService,
                                    PipelineOrchestrator pipelineOrchestrator,
                                    TieredStrategyProperties tieredStrategyProperties) {
        this(
                unifiedVectorService,
                dataStore,
                eventEnricher,
                promptTemplate,
                behaviorVectorService,
                baselineLearningService,
                securityLearningService,
                baselineSeedService,
                threatIntelligenceService,
                threatKnowledgePackService,
                null,
                promptContextAuthorizationService,
                promptContextAuditForwardingService,
                pipelineOrchestrator,
                tieredStrategyProperties);
    }

    public Layer1ContextualStrategy(UnifiedVectorService unifiedVectorService,
                                    SecurityContextDataStore dataStore,
                                    SecurityEventEnricher eventEnricher,
                                    SecurityDecisionStandardPromptTemplate promptTemplate,
                                    BehaviorVectorService behaviorVectorService,
                                    BaselineLearningService baselineLearningService,
                                    SecurityLearningService securityLearningService,
                                    SaasBaselineSeedService baselineSeedService,
                                    SaasThreatIntelligenceService threatIntelligenceService,
                                    SaasThreatKnowledgePackService threatKnowledgePackService,
                                    SaasDetectionStrategyPackService detectionStrategyPackService,
                                    PromptContextAuthorizationService promptContextAuthorizationService,
                                    PromptContextAuditForwardingService promptContextAuditForwardingService,
                                    PipelineOrchestrator pipelineOrchestrator,
                                    TieredStrategyProperties tieredStrategyProperties) {
        this(
                unifiedVectorService,
                dataStore,
                eventEnricher,
                promptTemplate,
                behaviorVectorService,
                baselineLearningService,
                securityLearningService,
                baselineSeedService,
                threatIntelligenceService,
                threatKnowledgePackService,
                detectionStrategyPackService,
                promptContextAuthorizationService,
                promptContextAuditForwardingService,
                pipelineOrchestrator,
                tieredStrategyProperties,
                null);
    }

    public Layer1ContextualStrategy(UnifiedVectorService unifiedVectorService,
                                    SecurityContextDataStore dataStore,
                                    SecurityEventEnricher eventEnricher,
                                    SecurityDecisionStandardPromptTemplate promptTemplate,
                                    BehaviorVectorService behaviorVectorService,
                                    BaselineLearningService baselineLearningService,
                                    SecurityLearningService securityLearningService,
                                    SaasBaselineSeedService baselineSeedService,
                                    SaasThreatIntelligenceService threatIntelligenceService,
                                    SaasThreatKnowledgePackService threatKnowledgePackService,
                                    SaasDetectionStrategyPackService detectionStrategyPackService,
                                    PromptContextAuthorizationService promptContextAuthorizationService,
                                    PromptContextAuditForwardingService promptContextAuditForwardingService,
                                     PipelineOrchestrator pipelineOrchestrator,
                                     TieredStrategyProperties tieredStrategyProperties,
                                     StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry) {
        this(
                unifiedVectorService,
                dataStore,
                eventEnricher,
                promptTemplate,
                behaviorVectorService,
                baselineLearningService,
                securityLearningService,
                baselineSeedService,
                threatIntelligenceService,
                threatKnowledgePackService,
                detectionStrategyPackService,
                promptContextAuthorizationService,
                promptContextAuditForwardingService,
                pipelineOrchestrator,
                tieredStrategyProperties,
                structuredOutputCapabilityRegistry,
                ForkJoinPool.commonPool());
    }

    public Layer1ContextualStrategy(UnifiedVectorService unifiedVectorService,
                                    SecurityContextDataStore dataStore,
                                    SecurityEventEnricher eventEnricher,
                                    SecurityDecisionStandardPromptTemplate promptTemplate,
                                    BehaviorVectorService behaviorVectorService,
                                    BaselineLearningService baselineLearningService,
                                    SecurityLearningService securityLearningService,
                                    SaasBaselineSeedService baselineSeedService,
                                    SaasThreatIntelligenceService threatIntelligenceService,
                                    SaasThreatKnowledgePackService threatKnowledgePackService,
                                    SaasDetectionStrategyPackService detectionStrategyPackService,
                                    PromptContextAuthorizationService promptContextAuthorizationService,
                                    PromptContextAuditForwardingService promptContextAuditForwardingService,
                                    PipelineOrchestrator pipelineOrchestrator,
                                    TieredStrategyProperties tieredStrategyProperties,
                                    StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry,
                                    ExecutorService ragRetrievalExecutor) {
        super(eventEnricher, promptTemplate,
                behaviorVectorService, unifiedVectorService, baselineLearningService,
                promptContextAuthorizationService, promptContextAuditForwardingService, tieredStrategyProperties,
                structuredOutputCapabilityRegistry);
        this.dataStore = dataStore;
        this.securityLearningService = securityLearningService;
        this.baselineSeedService = baselineSeedService;
        this.threatIntelligenceService = threatIntelligenceService;
        this.threatKnowledgePackService = threatKnowledgePackService;
        this.detectionStrategyPackService = detectionStrategyPackService;
        this.pipelineOrchestrator = pipelineOrchestrator;
        this.ragRetrievalExecutor = ragRetrievalExecutor != null ? ragRetrievalExecutor : ForkJoinPool.commonPool();

        TieredStrategyProperties.Layer1.Cache cacheConfig = tieredStrategyProperties.getLayer1().getCache();
        this.sessionContextCache = Caffeine.newBuilder()
                .maximumSize(cacheConfig.getMaxSize())
                .expireAfterAccess(cacheConfig.getTtlMinutes(), TimeUnit.MINUTES)
                .recordStats()
                .build();
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {

        SecurityDecision decision = analyzeWithContext(event);
        ZeroTrustAction autonomousAction = decision.resolveAutonomousAction();
        boolean shouldEscalate = autonomousAction == ZeroTrustAction.ESCALATE;
        String action = decision.getAction() != null ? decision.getAction().name() : null;

        return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessedAt(LocalDateTime.now())
                .riskScore(null)
                .confidence(decision.getConfidence())
                .llmAuditRiskScore(decision.resolveAuditRiskScore())
                .llmAuditConfidence(decision.resolveAuditConfidence())
                .indicators(new ArrayList<>())
                .recommendedActions(List.of(mapActionToRecommendation(autonomousAction)))
                .strategyName("Layer1-Contextual")
                .shouldEscalate(shouldEscalate)
                .action(action)
                .autonomousAction(autonomousAction.name())
                .llmDecisionPresent(decision.getLlmDecisionPresent())
                .technicalFallbackApplied(decision.getTechnicalFallbackApplied())
                .technicalFallbackCategory(decision.getTechnicalFallbackCategory())
                .technicalFallbackReason(decision.getTechnicalFallbackReason())
                .technicalFallbackAction(decision.getTechnicalFallbackAction())
                .reasoning(decision.getReasoning())
                .autonomyConstraintApplied(decision.getAutonomyConstraintApplied())
                .autonomyConstraintReasons(decision.getAutonomyConstraintReasons())
                .autonomyConstraintSummary(decision.getAutonomyConstraintSummary())
                .build();
    }

    public SecurityDecision analyzeWithContext(SecurityEvent event) {
        log.info("[Layer1ContextualStrategy.analyzeWithContext] Start processing event {}", event.getEventId());
        long startTime = System.currentTimeMillis();
        long sessionContextMs = 0L;
        long ragSearchMs = 0L;
        long behaviorAnalysisMs = 0L;
        long promptBuildMs = 0L;
        long llmExecutionMs = 0L;
        long responseParseMs = 0L;
        long promptTelemetryMs = 0L;
        long decisionConvertMs = 0L;
        long runtimeTelemetryMs = 0L;
        long escalateClassificationMs = 0L;
        long contextEnrichMs = 0L;
        long postProcessMs = 0L;

        try {
            long sessionContextStart = System.currentTimeMillis();
            SessionContext sessionContext = buildSessionContext(event);
            sessionContextMs = System.currentTimeMillis() - sessionContextStart;

            long ragSearchStart = System.currentTimeMillis();
            RagRetrievalOutcome ragOutcome = retrieveRelatedContextWithinBudget(event);
            List<Document> relatedDocuments = ragOutcome.relatedDocuments();
            List<String> similarEvents = ragOutcome.similarEvents();
            ragSearchMs = System.currentTimeMillis() - ragSearchStart;


            long behaviorAnalysisStart = System.currentTimeMillis();
            BaseBehaviorAnalysis behaviorAnalysis = analyzeBehaviorPatternsBase(event, baselineLearningService, similarEvents);
            behaviorAnalysisMs = System.currentTimeMillis() - behaviorAnalysisStart;

            long promptBuildStart = System.currentTimeMillis();
            SecurityDecisionStandardPromptTemplate.SessionContext sessionCtx = convertToTemplateSessionContext(sessionContext);
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorCtx = convertToTemplateBehaviorAnalysis(behaviorAnalysis, event);
            annotateThreatKnowledgeContext(event, behaviorCtx);

            cacheEscalationContext(event.getEventId(), sessionCtx, behaviorCtx, relatedDocuments);

            promptBuildMs = System.currentTimeMillis() - promptBuildStart;
            long llmTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getLlmMs();

            SecurityResponse response = null;
            SecurityDecisionResponse pipelineResponse = null;
            clearPromptRuntimeTelemetry(event);
            if (pipelineOrchestrator != null) {
                long llmExecutionStart = System.currentTimeMillis();
                // Apply layer1.timeout.llmMs to the blocking pipeline call so a stalled
                // upstream model never wedges Layer 1 indefinitely. Reactor surfaces a
                // timeout as IllegalStateException, which the outer catch converts to a
                // technical fallback decision (ESCALATE to Layer 2).
                pipelineResponse = executeSecurityDecisionPipeline(
                                pipelineOrchestrator,
                                event,
                                sessionCtx,
                                behaviorCtx,
                                relatedDocuments)
                        .block(Duration.ofMillis(llmTimeoutMs));
                llmExecutionMs = System.currentTimeMillis() - llmExecutionStart;

                if (pipelineResponse == null) {
                    throw new IllegalStateException("Layer1 structured security decision pipeline returned null");
                }

                long responseParseStart = System.currentTimeMillis();
                response = validateAndFixResponse(pipelineResponse.toSecurityResponse());
                responseParseMs = System.currentTimeMillis() - responseParseStart;
                long promptTelemetryStart = System.currentTimeMillis();
                capturePromptRuntimeTelemetry(event, pipelineResponse);
                promptTelemetryMs = System.currentTimeMillis() - promptTelemetryStart;
            } else {
                throw new IllegalStateException("Layer1 PipelineOrchestrator not available");
            }

            long decisionConvertStart = System.currentTimeMillis();
            SecurityDecision decision = convertToSecurityDecision(response, event);
            decisionConvertMs = System.currentTimeMillis() - decisionConvertStart;
            long runtimeTelemetryStart = System.currentTimeMillis();
            decision.setLlmDecisionPresent(true);
            decision.setTechnicalFallbackApplied(false);
            applySecurityDecisionRuntimeTelemetry(decision, pipelineResponse);
            decision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            decision.setProcessingLayer(1);
            runtimeTelemetryMs = System.currentTimeMillis() - runtimeTelemetryStart;
            long escalateClassificationStart = System.currentTimeMillis();
            recordLayer1EscalateClassification(event, decision);
            escalateClassificationMs = System.currentTimeMillis() - escalateClassificationStart;

            if (securityLearningService != null) {
                long postProcessStart = System.currentTimeMillis();
                securityLearningService.postProcessDecision(event, decision);
                postProcessMs = System.currentTimeMillis() - postProcessStart;
            }

            long contextEnrichStart = System.currentTimeMillis();
            enrichDecisionWithContext(
                    decision,
                    sessionContext,
                    behaviorAnalysis,
                    sessionContextMs,
                    ragSearchMs,
                    behaviorAnalysisMs,
                    promptBuildMs,
                    llmExecutionMs,
                    responseParseMs,
                    postProcessMs);
            contextEnrichMs = System.currentTimeMillis() - contextEnrichStart;
            recordLayer1TimingMetadata(
                    event,
                    sessionContextMs,
                    ragSearchMs,
                    behaviorAnalysisMs,
                    promptBuildMs,
                    llmExecutionMs,
                    responseParseMs,
                    postProcessMs,
                    promptTelemetryMs,
                    decisionConvertMs,
                    runtimeTelemetryMs,
                    escalateClassificationMs,
                    contextEnrichMs,
                    System.currentTimeMillis() - startTime);

            log.info("[Layer1ContextualStrategy.analyzeWithContext] End. SessionContext: {} ms, RAG Search: {} ms, Behavior Analysis: {} ms, Prompt Build: {} ms, LLM Execution: {} ms, Response Parse: {} ms, Prompt Telemetry: {} ms, Decision Convert: {} ms, Runtime Telemetry: {} ms, Escalate Classification: {} ms, Post Process: {} ms, Context Enrich: {} ms. Total: {} ms",
                    sessionContextMs, ragSearchMs, behaviorAnalysisMs, promptBuildMs, llmExecutionMs, responseParseMs, promptTelemetryMs, decisionConvertMs, runtimeTelemetryMs, escalateClassificationMs, postProcessMs, contextEnrichMs, (System.currentTimeMillis() - startTime));

            return decision;

        } catch (Exception e) {
            log.error("Layer 1 analysis failed for event {}", event.getEventId(), e);
            SecurityDecision fallbackDecision = createTechnicalFallbackDecision(
                    event,
                    ZeroTrustAction.ESCALATE,
                    "[AI Native] Layer 1 analysis failed - escalating to Layer 2",
                    resolveTechnicalFailureCategory(e),
                    startTime,
                    1);
            recordLayer1EscalateClassification(event, fallbackDecision);
            return fallbackDecision;
        }
    }

    public Mono<SecurityDecision> analyzeWithContextAsync(SecurityEvent event) {
        long totalTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getTotalMs();
        long startTime = System.currentTimeMillis();
        return Mono.fromCallable(() -> analyzeWithContext(event))
                .timeout(Duration.ofMillis(totalTimeoutMs))
                .onErrorResume(throwable -> {
                    log.error("[Layer1][AI Native v4.3.0] Async analysis failed or timed out ({}ms)",
                            totalTimeoutMs, throwable);
                    SecurityDecision fallbackDecision = createTechnicalFallbackDecision(
                            event,
                            ZeroTrustAction.ESCALATE,
                            "[AI Native] Layer 1 async analysis failed - escalating to Layer 2",
                            resolveTechnicalFailureCategory(throwable),
                            startTime,
                            1);
                    recordLayer1EscalateClassification(event, fallbackDecision);
                    return Mono.just(fallbackDecision);
                });
    }

    private SessionContext buildSessionContext(SecurityEvent event) {
        String sessionId = event.getSessionId();
        if (sessionId != null) {
            SessionContext cached = sessionContextCache.getIfPresent(sessionId);
            if (cached != null && cached.isValid()) {
                cached.addEvent(event);
                return cached;
            }
        }

        SessionContext context = new SessionContext();
        context.setSessionId(sessionId);
        context.setUserId(event.getUserId());
        context.setIpAddress(event.getSourceIp());
        context.setStartTime(LocalDateTime.now());

        if (event.getMetadata() != null) {
            Object authMethodObj = event.getMetadata().get("authMethod");
            if (authMethodObj instanceof String) {
                context.setAuthMethod((String) authMethodObj);
            }
        }

        if (event.getUserAgent() != null) {
            context.setUserAgent(event.getUserAgent());
        }

        if (sessionId != null && dataStore != null) {
            try {
                List<String> recentActions = dataStore.getRecentSessionActions(sessionId, 10);
                if (!recentActions.isEmpty()) {
                    List<String> promptRelevantActions = recentActions.stream()
                            .filter(PromptRelevantRequestPathPolicy::isPromptRelevantActionSummary)
                            .toList();
                    if (!promptRelevantActions.isEmpty()) {
                        context.setRecentActions(promptRelevantActions);
                        context.setAccessFrequency(promptRelevantActions.size());
                    }
                }
            } catch (Exception e) {
                log.error("[Layer1] Failed to retrieve recent actions: {}", e.getMessage());
            }
        }
        if (context.getAccessFrequency() <= 0 && event.getMetadata() != null) {
            Object recentRequestCountObj = event.getMetadata().get("recentRequestCount");
            if (recentRequestCountObj instanceof Number) {
                context.setAccessFrequency(((Number) recentRequestCountObj).intValue());
            }
        }
        context.addEvent(event);
        if (sessionId != null && context.getUserId() != null) {
            sessionContextCache.put(sessionId, context);
        }
        return context;
    }

    private List<Document> searchRelatedContext(SecurityEvent event) {
        double similarityThreshold = tieredStrategyProperties.getLayer1().getRag().getSimilarityThreshold();
        int topK = tieredStrategyProperties.getLayer1().getVectorSearchLimit();
        return searchRelatedContextBase(event, topK, similarityThreshold);
    }

    private RagRetrievalOutcome retrieveRelatedContextWithinBudget(SecurityEvent event) {
        long ragTimeoutMs = Math.max(1L, tieredStrategyProperties.getLayer1().getTimeout().getRagMs());
        long ragWaitMs = resolveLayer1RagWaitMs(event, ragTimeoutMs);
        boolean officialVerification = isOfficialVerificationEvent(event);
        Future<RagRetrievalOutcome> future = null;
        try {
            future = ragRetrievalExecutor.submit(() -> {
                List<Document> relatedDocuments = searchRelatedContext(event);
                List<String> similarEvents = extractSimilarEventsSummary(relatedDocuments);
                return new RagRetrievalOutcome(relatedDocuments, similarEvents);
            });

            long retrievalStartedAt = System.currentTimeMillis();
            RagRetrievalOutcome outcome = future.get(ragWaitMs, TimeUnit.MILLISECONDS);
            long retrievalElapsedMs = System.currentTimeMillis() - retrievalStartedAt;
            annotateRagInteractiveBudget(event, ragWaitMs, ragTimeoutMs, false);
            if (!hasRagUnavailableMetadata(event)) {
                annotateRagRetrievalResult(event, outcome.relatedDocuments(), false, null, false);
            } else if (isRagBudgetInterrupted(event) || retrievalElapsedMs >= Math.max(1L, ragWaitMs - 25L)) {
                annotateRagBudgetExpired(event, ragWaitMs, retrievalElapsedMs);
            }
            return outcome;
        } catch (TimeoutException timeoutException) {
            if (future != null) {
                future.cancel(true);
            }
            annotateRagRetrievalResult(event, List.of(), true, timeoutException, true);
            annotateRagInteractiveBudget(event, ragWaitMs, ragTimeoutMs, false);
            log.warn("[Layer1] RAG retrieval exceeded hot-path wait budget after {}ms for event {}. fullTimeoutMs={}, cancelled=true",
                    ragWaitMs,
                    event != null ? event.getEventId() : "unknown",
                    ragTimeoutMs,
                    timeoutException);
            return RagRetrievalOutcome.empty();
        } catch (ExecutionException executionException) {
            Throwable cause = executionException.getCause() instanceof Exception
                    ? executionException.getCause()
                    : executionException;
            Exception ragFailure = cause instanceof Exception
                    ? (Exception) cause
                    : new RuntimeException(cause);
            annotateRagRetrievalResult(event, List.of(), true, ragFailure, false);
            log.error("[Layer1] RAG retrieval failed for event {}. Continuing with empty relatedDocuments.",
                    event != null ? event.getEventId() : "unknown",
                    ragFailure);
            return RagRetrievalOutcome.empty();
        } catch (Exception ragFailure) {
            annotateRagRetrievalResult(event, List.of(), true, ragFailure, false);
            log.error("[Layer1] RAG retrieval failed for event {}. Continuing with empty relatedDocuments.",
                    event != null ? event.getEventId() : "unknown",
                    ragFailure);
            return RagRetrievalOutcome.empty();
        }
    }

    private long resolveLayer1RagWaitMs(SecurityEvent event, long ragTimeoutMs) {
        long fullTimeoutMs = Math.max(1L, ragTimeoutMs);
        if (isOfficialVerificationEvent(event)) {
            return fullTimeoutMs;
        }
        long interactiveWaitMs = tieredStrategyProperties.getLayer1().getTimeout().getInteractiveRagWaitMs();
        if (interactiveWaitMs <= 0L) {
            return fullTimeoutMs;
        }
        return Math.min(fullTimeoutMs, Math.max(1L, interactiveWaitMs));
    }

    private boolean isOfficialVerificationEvent(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return false;
        }
        Map<String, Object> metadata = event.getMetadata();
        Object boundaryMode = metadata.get("officialVerificationDecisionBoundaryMode");
        if (boundaryMode != null && "OFFICIAL_VERIFICATION_RUNTIME".equalsIgnoreCase(boundaryMode.toString())) {
            return true;
        }
        Object scenario = metadata.get("scenario");
        if (scenario != null && scenario.toString().startsWith("OFFICIAL_VERIFICATION")) {
            return true;
        }
        Object requestPath = firstPresent(metadata, "requestPath", "path", "resourceUrl", "requestUri");
        return requestPath != null
                && requestPath.toString().contains("/admin/api/enterprise/verification/runtime/probe/");
    }

    private Object firstPresent(Map<String, Object> metadata, String... keys) {
        if (metadata == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private void annotateRagInteractiveBudget(SecurityEvent event,
                                              long ragWaitMs,
                                              long ragTimeoutMs,
                                              boolean backgroundWarmup) {
        Map<String, Object> metadata = mutableMetadata(event);
        if (metadata == null) {
            return;
        }
        metadata.put("ragInteractiveWaitMs", Math.max(1L, ragWaitMs));
        metadata.put("ragFullTimeoutMs", Math.max(1L, ragTimeoutMs));
        metadata.put("ragRuntimeBudgetPolicy", ragWaitMs < ragTimeoutMs
                ? (backgroundWarmup ? "INTERACTIVE_WAIT_WITH_BACKGROUND_WARMUP" : "INTERACTIVE_WAIT_CANCEL_ON_TIMEOUT")
                : "FULL_WAIT");
        if (backgroundWarmup) {
            metadata.put("ragBackgroundWarmup", true);
            metadata.put("ragFailureMessage",
                    "RAG retrieval exceeded the interactive hot-path budget; background lookup continues for cache warm-up.");
        } else {
            metadata.remove("ragBackgroundWarmup");
        }
        if (Boolean.TRUE.equals(metadata.get("ragTimedOut"))) {
            metadata.put("ragTimeoutMs", Math.max(1L, ragWaitMs));
        }
    }

    private Map<String, Object> mutableMetadata(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null) {
            metadata = new LinkedHashMap<>();
            event.setMetadata(metadata);
        } else if (!(metadata instanceof LinkedHashMap) && !(metadata instanceof HashMap)) {
            metadata = new LinkedHashMap<>(metadata);
            event.setMetadata(metadata);
        }
        return metadata;
    }
    private SecurityDecisionStandardPromptTemplate.SessionContext convertToTemplateSessionContext(SessionContext sessionContext) {
        SecurityDecisionStandardPromptTemplate.SessionContext ctx = new SecurityDecisionStandardPromptTemplate.SessionContext();
        ctx.setSessionId(sessionContext.getSessionId());
        ctx.setUserId(sessionContext.getUserId());
        ctx.setAuthMethod(sessionContext.getAuthMethod());
        ctx.setRecentActions(sessionContext.getRecentActions());

        if (sessionContext.getStartTime() != null) {
            long minutes = Duration.between(
                    sessionContext.getStartTime(),
                    LocalDateTime.now()
            ).toMinutes();
            ctx.setSessionAgeMinutes((int) Math.max(0, minutes));
        }
        ctx.setRequestCount(sessionContext.getAccessFrequency());
        return ctx;
    }

    private SecurityDecisionStandardPromptTemplate.BehaviorAnalysis convertToTemplateBehaviorAnalysis(
            BaseBehaviorAnalysis behaviorAnalysis,
            SecurityEvent event) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis ctx = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        ctx.setBaselineEstablished(behaviorAnalysis.isBaselineEstablished());

        enrichBehaviorAnalysisWithRuntimeLearningSupport(
                ctx,
                event,
                baselineSeedService,
                threatIntelligenceService,
                threatKnowledgePackService,
                detectionStrategyPackService);

        if (!StringUtils.hasText(ctx.getPreviousUserAgentOS())
                && ctx.getPersonalBaselineEvidence() != null
                && !ctx.getPersonalBaselineEvidence().operatingSystems().isEmpty()) {
            ctx.setPreviousUserAgentOS(ctx.getPersonalBaselineEvidence().operatingSystems().get(0));
        }

        return ctx;
    }

    private SecurityDecision convertToSecurityDecision(SecurityResponse response,
                                                       SecurityEvent event) {
        return convertToSecurityDecisionBase(response, event);
    }

    private void annotateRagRetrievalResult(
            SecurityEvent event,
            List<Document> relatedDocuments,
            boolean ragUnavailable,
            Exception ragFailure,
            boolean ragTimedOut) {
        if (event == null) {
            return;
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null) {
            metadata = new LinkedHashMap<>();
            event.setMetadata(metadata);
        } else if (!(metadata instanceof HashMap)) {
            metadata = new LinkedHashMap<>(metadata);
            event.setMetadata(metadata);
        }

        if (ragUnavailable && !ragTimedOut && isRagBudgetFailure(ragFailure)) {
            long ragTimeoutMs = Math.max(1L, tieredStrategyProperties.getLayer1().getTimeout().getRagMs());
            annotateRagBudgetExpired(event, ragTimeoutMs, ragTimeoutMs);
            return;
        }

        metadata.put("ragUnavailable", ragUnavailable);
        metadata.put("ragTimedOut", ragTimedOut);
        int relatedDocumentCount = relatedDocuments != null ? relatedDocuments.size() : 0;
        boolean hasSearchLedgerMetadata = hasRagSearchLedgerMetadata(metadata);
        metadata.put("ragSearchExecuted", true);
        if (!hasSearchLedgerMetadata || ragUnavailable || ragTimedOut) {
            metadata.put("ragRetrievalState", ragRetrievalState(ragUnavailable, ragTimedOut, relatedDocumentCount));
        }
        Object retrievalState = metadata.get("ragRetrievalState");
        boolean permissionFiltered = Boolean.TRUE.equals(metadata.get("ragPermissionFiltered"))
                || "PERMISSION_FILTERED".equals(retrievalState);
        metadata.put("ragProjectionState", relatedDocumentCount > 0
                ? "PROJECTED"
                : (permissionFiltered ? "PERMISSION_FILTERED_DECLARED" : "ZERO_RESULTS_DECLARED"));
        metadata.put("ragProjectedToFinalPrompt", relatedDocumentCount > 0);
        metadata.put("ragStatusProjectedToFinalPrompt", true);
        metadata.put("relatedDocumentCount", relatedDocumentCount);
        metadata.put("relatedDocumentsCount", relatedDocumentCount);
        metadata.putIfAbsent("ragCandidateDocumentCount", relatedDocumentCount);
        metadata.putIfAbsent("ragAuthorizedDocumentCount", relatedDocumentCount);
        metadata.putIfAbsent("ragDeniedDocumentCount", 0);
        metadata.putIfAbsent("ragPermissionFiltered", permissionFiltered);
        if (relatedDocumentCount == 0) {
            metadata.putIfAbsent("ragAbsenceReason", ragUnavailable
                    ? (ragTimedOut ? "TIMEOUT" : "UNAVAILABLE")
                    : (permissionFiltered ? "PERMISSION_FILTER_EXCLUDED" : "ZERO_RESULTS"));
        } else {
            metadata.remove("ragAbsenceReason");
        }
        if (!ragUnavailable) {
            metadata.remove("ragFailureType");
            metadata.remove("ragFailureMessage");
            metadata.remove("ragTimeoutMs");
            return;
        }

        metadata.put("ragFailureType", ragFailure != null ? ragFailure.getClass().getName() : "unknown");
        metadata.put("ragFailureMessage",
                ragFailure != null && ragFailure.getMessage() != null ? ragFailure.getMessage() : "RAG retrieval unavailable");
        if (ragTimedOut) {
            metadata.put("ragTimeoutMs", Math.max(1L, tieredStrategyProperties.getLayer1().getTimeout().getRagMs()));
        } else {
            metadata.remove("ragTimeoutMs");
        }
    }

    private boolean hasRagSearchLedgerMetadata(Map<String, Object> metadata) {
        return metadata.containsKey("ragRetrievalState")
                || metadata.containsKey("ragCandidateDocumentCount")
                || metadata.containsKey("ragAuthorizedDocumentCount")
                || metadata.containsKey("ragDeniedDocumentCount")
                || metadata.containsKey("ragPermissionFiltered")
                || metadata.containsKey("requestedDocumentCount")
                || metadata.containsKey("allowedDocumentCount")
                || metadata.containsKey("deniedDocumentCount");
    }

    private String ragRetrievalState(boolean ragUnavailable, boolean ragTimedOut, int relatedDocumentCount) {
        if (ragTimedOut) {
            return "TIMEOUT";
        }
        if (ragUnavailable) {
            return "UNAVAILABLE";
        }
        return relatedDocumentCount > 0 ? "AVAILABLE" : "ZERO_RESULTS";
    }

    
    private void annotateRagBudgetExpired(SecurityEvent event, long ragTimeoutMs, long elapsedMs) {
        if (event == null) {
            return;
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null) {
            metadata = new LinkedHashMap<>();
            event.setMetadata(metadata);
        }
        metadata.put("ragUnavailable", false);
        metadata.put("ragTimedOut", true);
        metadata.put("ragSearchExecuted", true);
        metadata.put("ragRetrievalState", "BUDGET_EXPIRED");
        metadata.put("ragAbsenceReason", "BUDGET_EXPIRED");
        metadata.put("ragProjectionState", "BUDGET_EXPIRED_DECLARED");
        metadata.put("ragProjectedToFinalPrompt", false);
        metadata.put("ragStatusProjectedToFinalPrompt", true);
        metadata.put("relatedDocumentCount", 0);
        metadata.put("relatedDocumentsCount", 0);
        metadata.put("ragTimeoutMs", Math.max(1L, ragTimeoutMs));
        metadata.put("ragElapsedMs", Math.max(0L, elapsedMs));
        metadata.remove("ragFailureType");
        metadata.remove("ragFailureMessage");
    }
    private boolean isRagBudgetFailure(Exception ragFailure) {
        if (ragFailure == null || ragFailure.getMessage() == null) {
            return false;
        }
        String normalized = ragFailure.getMessage().toLowerCase(Locale.ROOT);
        return normalized.contains("interrupted") || normalized.contains("timed out");
    }

    private boolean isRagBudgetInterrupted(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return false;
        }
        Object failureMessage = event.getMetadata().get("ragFailureMessage");
        if (!(failureMessage instanceof String message)) {
            return false;
        }
        String normalized = message.toLowerCase(Locale.ROOT);
        return normalized.contains("interrupted") || normalized.contains("timed out");
    }

    private boolean hasRagUnavailableMetadata(SecurityEvent event) {
        return event != null
                && event.getMetadata() != null
                && Boolean.TRUE.equals(event.getMetadata().get("ragUnavailable"));
    }

    private void recordLayer1TimingMetadata(
            SecurityEvent event,
            long sessionContextMs,
            long ragSearchMs,
            long behaviorAnalysisMs,
            long promptBuildMs,
            long pipelineBlockMs,
            long responseValidateMs,
            long postProcessMs,
            long promptTelemetryMs,
            long decisionConvertMs,
            long runtimeTelemetryMs,
            long escalateClassificationMs,
            long contextEnrichMs,
            long totalMs) {
        if (event == null) {
            return;
        }
        event.addMetadata("layer1SessionContextMs", sessionContextMs);
        event.addMetadata("layer1RagSearchMs", ragSearchMs);
        event.addMetadata("layer1BehaviorAnalysisMs", behaviorAnalysisMs);
        event.addMetadata("layer1PromptPreparationMs", promptBuildMs);
        event.addMetadata("layer1PipelineBlockMs", pipelineBlockMs);
        event.addMetadata("layer1ResponseValidateMs", responseValidateMs);
        event.addMetadata("layer1PostProcessMs", postProcessMs);
        event.addMetadata("layer1PromptTelemetryCaptureMs", promptTelemetryMs);
        event.addMetadata("layer1DecisionConvertMs", decisionConvertMs);
        event.addMetadata("layer1RuntimeTelemetryApplyMs", runtimeTelemetryMs);
        event.addMetadata("layer1EscalateClassificationMs", escalateClassificationMs);
        event.addMetadata("layer1ContextEnrichMs", contextEnrichMs);
        long accountedMs = sessionContextMs + ragSearchMs + behaviorAnalysisMs + promptBuildMs + pipelineBlockMs
                + responseValidateMs + postProcessMs + promptTelemetryMs + decisionConvertMs + runtimeTelemetryMs
                + escalateClassificationMs + contextEnrichMs;
        long unaccountedMs = Math.max(0L, totalMs - accountedMs);
        event.addMetadata("layer1UnaccountedMs", unaccountedMs);
        event.addMetadata("layer1TotalMs", totalMs);
        event.addMetadata("ragVectorMs", ragSearchMs);
        event.addMetadata("pipelineBlockMs", pipelineBlockMs);
        log.info("[Layer1ContextualStrategy.timing] eventId={} sessionContextMs={} ragSearchMs={} behaviorAnalysisMs={} promptPreparationMs={} pipelineBlockMs={} responseValidateMs={} promptTelemetryMs={} decisionConvertMs={} runtimeTelemetryMs={} escalateClassificationMs={} postProcessMs={} contextEnrichMs={} unaccountedMs={} totalMs={}",
                event.getEventId(),
                sessionContextMs,
                ragSearchMs,
                behaviorAnalysisMs,
                promptBuildMs,
                pipelineBlockMs,
                responseValidateMs,
                promptTelemetryMs,
                decisionConvertMs,
                runtimeTelemetryMs,
                escalateClassificationMs,
                postProcessMs,
                contextEnrichMs,
                unaccountedMs,
                totalMs);
    }
    private void recordLayer1EscalateClassification(SecurityEvent event, SecurityDecision decision) {
        if (event == null || decision == null) {
            return;
        }
        ZeroTrustAction action = decision.resolveAutonomousAction();
        boolean technicalFallback = Boolean.TRUE.equals(decision.getTechnicalFallbackApplied());
        boolean technicalFallbackEscalate = technicalFallback && action == ZeroTrustAction.ESCALATE;
        boolean modelDecidedEscalate = !technicalFallback && action == ZeroTrustAction.ESCALATE;
        String reasonType;
        if (technicalFallbackEscalate) {
            reasonType = "TECHNICAL_FALLBACK_ESCALATE";
        } else if (modelDecidedEscalate) {
            reasonType = "MODEL_DECIDED_ESCALATE";
        } else {
            reasonType = "NOT_ESCALATED";
        }
        event.addMetadata("layer1EscalateReasonType", reasonType);
        event.addMetadata("layer1ModelDecidedEscalate", modelDecidedEscalate);
        event.addMetadata("layer1TechnicalFallbackEscalate", technicalFallbackEscalate);
        event.addMetadata("layer1TechnicalFallbackApplied", technicalFallback);
        if (decision.getTechnicalFallbackCategory() != null) {
            event.addMetadata("layer1TechnicalFallbackCategory", decision.getTechnicalFallbackCategory());
        }
        if (decision.getTechnicalFallbackReason() != null) {
            event.addMetadata("layer1TechnicalFallbackReason", decision.getTechnicalFallbackReason());
        }
    }
    private void enrichDecisionWithContext(SecurityDecision decision,
                                           SessionContext sessionContext,
                                           BaseBehaviorAnalysis behaviorAnalysis,
                                           long sessionContextMs,
                                           long ragSearchMs,
                                           long behaviorAnalysisMs,
                                           long promptBuildMs,
                                           long llmExecutionMs,
                                           long responseParseMs,
                                           long postProcessMs) {

        Map<String, Object> sessionData = new HashMap<>();
        sessionData.put("sessionId", sessionContext.getSessionId());
        sessionData.put("userId", sessionContext.getUserId());
        sessionData.put("sessionDuration", sessionContext.getSessionDuration());
        sessionData.put("accessFrequency", sessionContext.getAccessFrequency());
        sessionData.put("sessionContextBuildMs", sessionContextMs);
        sessionData.put("ragSearchMs", ragSearchMs);
        sessionData.put("behaviorAnalysisMs", behaviorAnalysisMs);
        sessionData.put("promptBuildMs", promptBuildMs);
        sessionData.put("llmExecutionMs", llmExecutionMs);
        sessionData.put("responseParseMs", responseParseMs);
        sessionData.put("postProcessMs", postProcessMs);
        sessionData.put("preLlmPreparationMs", sessionContextMs + ragSearchMs + behaviorAnalysisMs + promptBuildMs);

        decision.setSessionContext(sessionData);
        if (decision.getBehaviorPatterns() == null) {
            decision.setBehaviorPatterns(new ArrayList<>());
        }
        decision.getBehaviorPatterns().addAll(behaviorAnalysis.getSimilarEvents());
    }

    @Override
    protected String getLayerName() {
        return "Layer1";
    }

    private String mapActionToRecommendation(ZeroTrustAction action) {
        return switch (action) {
            case ALLOW -> "ALLOW";
            case BLOCK -> "BLOCK_IMMEDIATELY";
            case CHALLENGE -> "REQUIRE_MFA";
            case ESCALATE, PENDING_ANALYSIS -> "ESCALATE_TO_EXPERT";
        };
    }

    private class SessionContext extends BaseSessionContext {

        public void addEvent(SecurityEvent event) {
            String requestPath = extractRequestPath(event);
            if (!PromptRelevantRequestPathPolicy.isPromptRelevantPath(requestPath)) {
                return;
            }
            accessFrequency++;

            int maxRecentActions = tieredStrategyProperties.getLayer1().getSession().getMaxRecentActions();
            if (recentActions.size() >= maxRecentActions) {
                recentActions.remove(0);
            }

            recentActions.add(buildActionSummary(event));
        }

        private String buildActionSummary(SecurityEvent event) {
            StringBuilder action = new StringBuilder();

            if (event.getTimestamp() != null) {
                action.append(String.format("%02d:%02d",
                        event.getTimestamp().getHour(),
                        event.getTimestamp().getMinute()));
            }
            action.append(" | ");

            if (event.getMetadata() != null) {
                Object method = event.getMetadata().get("httpMethod");
                if (method != null) action.append(method).append(" ");
            }

            String path = null;
            if (event.getMetadata() != null) {
                Object p = event.getMetadata().get("requestPath");
                if (p == null) p = event.getMetadata().get("targetResource");
                if (p != null) path = p.toString();
            }
            if (path != null) {
                action.append(path);
            } else if (event.getDescription() != null) {
                action.append(event.getDescription());
            }

            action.append(" | ");
            if (event.getSourceIp() != null) action.append(event.getSourceIp());

            return action.toString();
        }

        private String extractRequestPath(SecurityEvent event) {
            if (event == null || event.getMetadata() == null) {
                return null;
            }
            Object requestPath = event.getMetadata().get("requestPath");
            if (requestPath == null) {
                requestPath = event.getMetadata().get("targetResource");
            }
            return requestPath != null ? requestPath.toString() : null;
        }
    }

    private record RagRetrievalOutcome(
            List<Document> relatedDocuments,
            List<String> similarEvents) {

        private static RagRetrievalOutcome empty() {
            return new RagRetrievalOutcome(List.of(), List.of());
        }
    }

}
