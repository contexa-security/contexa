package io.contexa.contexacore.autonomous.tiered.strategy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.context.policy.PromptRelevantRequestPathPolicy;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditForwardingService;
import io.contexa.contexacore.autonomous.saas.SaasBaselineSeedService;
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
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Slf4j
public class Layer1ContextualStrategy extends AbstractTieredStrategy {

    private final SecurityContextDataStore dataStore;
    private final SecurityLearningService securityLearningService;
    private final SaasBaselineSeedService baselineSeedService;
    private final SaasThreatIntelligenceService threatIntelligenceService;
    private final SaasThreatKnowledgePackService threatKnowledgePackService;
    private final PipelineOrchestrator pipelineOrchestrator;
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
        super(eventEnricher, promptTemplate,
                behaviorVectorService, unifiedVectorService, baselineLearningService,
                promptContextAuthorizationService, promptContextAuditForwardingService, tieredStrategyProperties);
        this.dataStore = dataStore;
        this.securityLearningService = securityLearningService;
        this.baselineSeedService = baselineSeedService;
        this.threatIntelligenceService = threatIntelligenceService;
        this.threatKnowledgePackService = threatKnowledgePackService;
        this.pipelineOrchestrator = pipelineOrchestrator;

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
        boolean shouldEscalate = decision.getAction() == ZeroTrustAction.ESCALATE;
        String action = decision.getAction() != null ? decision.getAction().name() : "ESCALATE";
        ZeroTrustAction autonomousAction = decision.resolveAutonomousAction();

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
                .reasoning(decision.getReasoning())
                .autonomyConstraintApplied(decision.getAutonomyConstraintApplied())
                .autonomyConstraintReasons(decision.getAutonomyConstraintReasons())
                .autonomyConstraintSummary(decision.getAutonomyConstraintSummary())
                .build();
    }

        public SecurityDecision analyzeWithContext(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        long sessionContextMs = 0L;
        long ragSearchMs = 0L;
        long behaviorAnalysisMs = 0L;
        long promptBuildMs = 0L;
        long llmExecutionMs = 0L;
        long responseParseMs = 0L;
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
            clearPromptRuntimeTelemetry(event);
            if (pipelineOrchestrator != null) {
                long llmExecutionStart = System.currentTimeMillis();
                SecurityDecisionResponse pipelineResponse = executeSecurityDecisionPipeline(
                                pipelineOrchestrator,
                                event,
                                sessionCtx,
                                behaviorCtx,
                                relatedDocuments)
                        .timeout(Duration.ofMillis(llmTimeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.error("[Layer1] Standard security pipeline failed, escalating to Layer 2: {}", event.getEventId(), e);
                            return Mono.just(SecurityDecisionResponse.fromSecurityResponse(createDefaultResponse()));
                        })
                        .block();
                llmExecutionMs = System.currentTimeMillis() - llmExecutionStart;

                long responseParseStart = System.currentTimeMillis();
                response = validateAndFixResponse(
                        pipelineResponse != null
                                ? pipelineResponse.toSecurityResponse()
                                : createDefaultResponse()
                );
                responseParseMs = System.currentTimeMillis() - responseParseStart;
                capturePromptRuntimeTelemetry(event, pipelineResponse);
            } else {
                log.error("[Layer1] PipelineOrchestrator not available");
                response = createDefaultResponse();
            }

            SecurityDecision decision = applyPromptConfidenceGuardrail(convertToSecurityDecision(response, event), event);
            decision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            decision.setProcessingLayer(1);

            if (securityLearningService != null) {
                long postProcessStart = System.currentTimeMillis();
                securityLearningService.postProcessDecision(event, decision);
                postProcessMs = System.currentTimeMillis() - postProcessStart;
            }

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

            return decision;

        } catch (Exception e) {
            log.error("Layer 1 analysis failed for event {}", event.getEventId(), e);
            return createFallbackDecision(startTime);
        }
    }

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
        var executor = Executors.newVirtualThreadPerTaskExecutor();
        CompletableFuture<RagRetrievalOutcome> future = null;
        try {
            future = CompletableFuture.supplyAsync(() -> {
                List<Document> relatedDocuments = searchRelatedContext(event);
                List<String> similarEvents = extractSimilarEventsSummary(relatedDocuments);
                return new RagRetrievalOutcome(relatedDocuments, similarEvents);
            }, executor);

            RagRetrievalOutcome outcome = future.get(ragTimeoutMs, TimeUnit.MILLISECONDS);
            annotateRagRetrievalResult(event, outcome.relatedDocuments(), false, null, false);
            return outcome;
        } catch (TimeoutException timeoutException) {
            if (future != null) {
                future.cancel(true);
            }
            annotateRagRetrievalResult(event, List.of(), true, timeoutException, true);
            log.error("[Layer1] RAG retrieval timed out after {}ms for event {}. Continuing with empty relatedDocuments.",
                    ragTimeoutMs,
                    event != null ? event.getEventId() : "unknown",
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
        } finally {
            executor.shutdownNow();
        }
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
        ctx.setSimilarEvents(behaviorAnalysis.getSimilarEvents());
        ctx.setBaselineContext(behaviorAnalysis.getBaselineContext());
        ctx.setBaselineEstablished(behaviorAnalysis.isBaselineEstablished());
        if (threatIntelligenceService != null) {
            ctx.setActiveThreatSignals(threatIntelligenceService.getPromptSignals());
        }
        if (threatKnowledgePackService != null) {
            ctx.setThreatKnowledgePack(threatKnowledgePackService.currentSnapshot());
        }



        if (behaviorAnalysis.getBaselineContext() != null) {
            String baselineOS = extractOSFromBaselineContext(behaviorAnalysis.getBaselineContext());
            ctx.setPreviousUserAgentOS(baselineOS);
        }

        enrichBehaviorAnalysisWithBaselineSupport(ctx, event, baselineSeedService);

        hydrateBehaviorAnalysisRuntimeFacts(ctx, event);

        if (threatIntelligenceService != null) {
            ctx.setThreatIntelligenceMatchContext(threatIntelligenceService.buildThreatContext(event, ctx));
        }
        if (threatKnowledgePackService != null) {
            ctx.setThreatKnowledgePackMatchContext(
                    threatKnowledgePackService.buildThreatKnowledgeContext(event, ctx));
        }

        return ctx;
    }

    private String extractOSFromBaselineContext(String baselineContext) {
        if (baselineContext == null || baselineContext.isEmpty()) {
            return null;
        }

        try {
            int uaRowIdx = baselineContext.indexOf("| UA");
            if (uaRowIdx != -1) {

                int rowEndIdx = baselineContext.indexOf("\n", uaRowIdx);
                if (rowEndIdx == -1) rowEndIdx = baselineContext.length();
                String uaRow = baselineContext.substring(uaRowIdx, rowEndIdx);
                String[] columns = uaRow.split("\\|");
                if (columns.length >= 4) {

                    String baselineColumn = columns[3].trim();
                    int startParen = baselineColumn.lastIndexOf("(");
                    int endParen = baselineColumn.lastIndexOf(")");
                    if (startParen != -1 && endParen > startParen) {
                        String os = baselineColumn.substring(startParen + 1, endParen);
                        return os.replace("...", "");
                    }
                }
            }

            int baselineIdx = baselineContext.indexOf("\"baseline\":");
            if (baselineIdx != -1) {
                int startParen = baselineContext.indexOf("(", baselineIdx);
                int endParen = baselineContext.indexOf(")", startParen);
                if (startParen != -1 && endParen > startParen) {
                    return baselineContext.substring(startParen + 1, endParen);
                }
            }
        } catch (Exception e) {
            log.error("[Layer1] Failed to extract OS from baseline context: {}", e.getMessage());
        }
        return null;
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
            metadata = new java.util.LinkedHashMap<>();
            event.setMetadata(metadata);
        } else if (!(metadata instanceof HashMap) && !(metadata instanceof java.util.LinkedHashMap)) {
            metadata = new java.util.LinkedHashMap<>(metadata);
            event.setMetadata(metadata);
        }

        metadata.put("ragUnavailable", ragUnavailable);
        metadata.put("ragTimedOut", ragTimedOut);
        metadata.put("relatedDocumentsCount", relatedDocuments != null ? relatedDocuments.size() : 0);
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

    private SecurityDecision createFallbackDecision(long startTime) {
        return SecurityDecision.builder()
                .action(ZeroTrustAction.ESCALATE)
                .analysisTime(startTime)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .processingLayer(1)
                .reasoning("[AI Native] Layer 1 analysis failed - escalating to Layer 2")
                .build();
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
                recentActions.removeFirst();
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


