package io.contexa.contexacore.autonomous.tiered.strategy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
public class Layer1ContextualStrategy extends AbstractTieredStrategy {

    private final SecurityContextDataStore dataStore;
    private final SecurityLearningService securityLearningService;
    private final Cache<String, SessionContext> sessionContextCache;
    private volatile LlmAnalysisEventListener llmEventListener;

    public Layer1ContextualStrategy(UnifiedLLMOrchestrator llmOrchestrator,
                                    UnifiedVectorService unifiedVectorService,
                                    SecurityContextDataStore dataStore,
                                    SecurityEventEnricher eventEnricher,
                                    SecurityPromptTemplate promptTemplate,
                                    BehaviorVectorService behaviorVectorService,
                                    BaselineLearningService baselineLearningService,
                                    SecurityLearningService securityLearningService,
                                    TieredStrategyProperties tieredStrategyProperties) {
        super(llmOrchestrator, eventEnricher, promptTemplate,
                behaviorVectorService, unifiedVectorService, baselineLearningService,
                tieredStrategyProperties);
        this.dataStore = dataStore;

        this.securityLearningService = securityLearningService;

        TieredStrategyProperties.Layer1.Cache cacheConfig = tieredStrategyProperties.getLayer1().getCache();
        this.sessionContextCache = Caffeine.newBuilder()
                .maximumSize(cacheConfig.getMaxSize())
                .expireAfterAccess(cacheConfig.getTtlMinutes(), TimeUnit.MINUTES)
                .recordStats()
                .build();
    }

    public void setLlmEventListener(LlmAnalysisEventListener listener) {
        this.llmEventListener = listener;
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {

        SecurityDecision decision = analyzeWithContext(event);
        boolean shouldEscalate = decision.getAction() == ZeroTrustAction.ESCALATE;
        String action = decision.getAction() != null ? decision.getAction().name() : "ESCALATE";

        return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessedAt(LocalDateTime.now())
                .riskScore(decision.getRiskScore())
                .confidence(decision.getConfidence())
                .strategyName("Layer1-Contextual")
                .shouldEscalate(shouldEscalate)
                .action(action)
                .reasoning(decision.getReasoning())
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

            // SSE: session context loaded
            if (llmEventListener != null) {
                Map<String, Object> sessionData = new HashMap<>();
                sessionData.put("sessionId", sessionContext.getSessionId());
                sessionData.put("authMethod", sessionContext.getAuthMethod());
                sessionData.put("accessFrequency", sessionContext.getAccessFrequency());
                sessionData.put("recentActionsCount", sessionContext.getRecentActions() != null ? sessionContext.getRecentActions().size() : 0);
                sessionData.put("sessionContextMs", sessionContextMs);
                llmEventListener.onSessionContextLoaded(event.getUserId(), sessionData);
            }

            long ragSearchStart = System.currentTimeMillis();
            List<Document> relatedDocuments = searchRelatedContext(event);
            List<String> similarEvents = extractSimilarEventsSummary(relatedDocuments);
            ragSearchMs = System.currentTimeMillis() - ragSearchStart;

            // SSE: RAG search complete
            if (llmEventListener != null) {
                llmEventListener.onRagSearchComplete(event.getUserId(), relatedDocuments != null ? relatedDocuments.size() : 0, ragSearchMs);
            }

            long behaviorAnalysisStart = System.currentTimeMillis();
            BaseBehaviorAnalysis behaviorAnalysis = analyzeBehaviorPatternsBase(event, baselineLearningService, similarEvents);
            behaviorAnalysisMs = System.currentTimeMillis() - behaviorAnalysisStart;

            // SSE: behavior analysis complete
            if (llmEventListener != null) {
                Map<String, Object> behaviorData = new HashMap<>();
                behaviorData.put("baselineEstablished", behaviorAnalysis.isBaselineEstablished());
                behaviorData.put("similarEventsCount", behaviorAnalysis.getSimilarEvents() != null ? behaviorAnalysis.getSimilarEvents().size() : 0);
                behaviorData.put("behaviorAnalysisMs", behaviorAnalysisMs);
                // isNewSession/isNewDevice from event metadata (set by HCADFilter)
                if (event.getMetadata() != null) {
                    Object newSession = event.getMetadata().get("isNewSession");
                    Object newDevice = event.getMetadata().get("isNewDevice");
                    if (newSession != null) behaviorData.put("isNewSession", newSession);
                    if (newDevice != null) behaviorData.put("isNewDevice", newDevice);
                }
                llmEventListener.onBehaviorAnalysisComplete(event.getUserId(), behaviorData);
            }

            long promptBuildStart = System.currentTimeMillis();
            SecurityPromptTemplate.SessionContext sessionCtx = convertToTemplateSessionContext(sessionContext);
            SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = convertToTemplateBehaviorAnalysis(behaviorAnalysis, event);

            cacheEscalationContext(event.getEventId(), sessionCtx, behaviorCtx, relatedDocuments);

            SecurityPromptTemplate.StructuredPrompt structured =
                    promptTemplate.buildStructuredPrompt(event, sessionCtx, behaviorCtx, relatedDocuments);
            promptBuildMs = System.currentTimeMillis() - promptBuildStart;
            long llmTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getLlmMs();

            // SSE: LLM execution start
            if (llmEventListener != null) {
                llmEventListener.onLlmExecutionStart(event.getUserId(), "1차 AI (모델: Qwen 2.5 7B)", promptBuildMs);
            }

            SecurityResponse response = null;
            if (llmOrchestrator != null) {
                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(List.of(
                                new SystemMessage(structured.systemText()),
                                new UserMessage(structured.userText()))))
                        .tier(1)
                        .securityTaskType(ExecutionContext.SecurityTaskType.CONTEXTUAL_ANALYSIS)
                        .timeoutMs((int) llmTimeoutMs)
                        .requestId(event.getEventId())
                        .userId(event.getUserId())
                        .sessionId(event.getSessionId())
                        .temperature(0.0)
                        .topP(1.0)
                        .build();

                long llmExecutionStart = System.currentTimeMillis();
                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(llmTimeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.error("[Layer1] LLM execution failed, escalating to Layer 2: {}", event.getEventId(), e);
                            return Mono.just("{\"riskScore\":0.7,\"confidence\":0.3,\"action\":\"ESCALATE\",\"reasoning\":\"[AI Native] LLM execution failed - escalating to Layer 2\",\"threatCategory\":\"UNKNOWN\"}");
                        })
                        .block();
                llmExecutionMs = System.currentTimeMillis() - llmExecutionStart;

                long responseParseStart = System.currentTimeMillis();
                response = parseJsonResponse(jsonResponse);
                responseParseMs = System.currentTimeMillis() - responseParseStart;

                // SSE: LLM execution complete
                if (llmEventListener != null) {
                    llmEventListener.onLlmExecutionComplete(event.getUserId(), llmExecutionMs, responseParseMs);
                }
            } else {
                log.error("[Layer1] UnifiedLLMOrchestrator not available");
                response = createDefaultResponse();
            }

            SecurityDecision decision = convertToSecurityDecision(response, event);
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

            Object recentRequestCountObj = event.getMetadata().get("recentRequestCount");
            if (recentRequestCountObj instanceof Number) {
                context.setAccessFrequency(((Number) recentRequestCountObj).intValue());
            }
        }

        if (event.getUserAgent() != null) {
            context.setUserAgent(event.getUserAgent());
        }

        if (sessionId != null && dataStore != null) {
            try {
                List<String> recentActions = dataStore.getRecentSessionActions(sessionId, 10);
                if (!recentActions.isEmpty()) {
                    context.setRecentActions(recentActions);
                }
            } catch (Exception e) {
                log.error("[Layer1] Failed to retrieve recent actions: {}", e.getMessage());
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

    private SecurityPromptTemplate.SessionContext convertToTemplateSessionContext(SessionContext sessionContext) {
        SecurityPromptTemplate.SessionContext ctx = new SecurityPromptTemplate.SessionContext();
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

    private SecurityPromptTemplate.BehaviorAnalysis convertToTemplateBehaviorAnalysis(
            BaseBehaviorAnalysis behaviorAnalysis,
            SecurityEvent event) {
        SecurityPromptTemplate.BehaviorAnalysis ctx = new SecurityPromptTemplate.BehaviorAnalysis();
        ctx.setSimilarEvents(behaviorAnalysis.getSimilarEvents());
        ctx.setBaselineContext(behaviorAnalysis.getBaselineContext());
        ctx.setBaselineEstablished(behaviorAnalysis.isBaselineEstablished());

        if (event != null && event.getMetadata() != null) {
            Map<String, Object> meta = event.getMetadata();
            Object isNewSession = meta.get("isNewSession");
            Object isNewDevice = meta.get("isNewDevice");
            if (isNewSession instanceof Boolean) {
                ctx.setIsNewSession((Boolean) isNewSession);
            }
            if (isNewDevice instanceof Boolean) {
                ctx.setIsNewDevice((Boolean) isNewDevice);
            }
        }

        if (event != null && event.getUserAgent() != null) {
            ctx.setCurrentUserAgentOS(
                    SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent()));
            ctx.setCurrentUserAgentBrowser(
                    SecurityEventEnricher.extractBrowserSignature(event.getUserAgent()));
        }

        if (behaviorAnalysis.getBaselineContext() != null) {
            String baselineOS = extractOSFromBaselineContext(behaviorAnalysis.getBaselineContext());
            ctx.setPreviousUserAgentOS(baselineOS);
        }

        if (event != null && event.getUserId() != null && baselineLearningService != null) {
            try {
                BaselineVector baseline = baselineLearningService.getBaseline(event.getUserId());
                if (baseline != null) {
                    ctx.setBaselineIpRanges(baseline.getNormalIpRanges());
                    ctx.setBaselineOperatingSystems(baseline.getNormalOperatingSystems());
                    ctx.setBaselineUserAgents(baseline.getNormalUserAgents());
                    ctx.setBaselineFrequentPaths(baseline.getFrequentPaths());
                    ctx.setBaselineAccessHours(baseline.getNormalAccessHours());
                    ctx.setBaselineAccessDays(baseline.getNormalAccessDays());
                    ctx.setBaselineUpdateCount(baseline.getUpdateCount());
                    ctx.setBaselineAvgTrustScore(baseline.getAvgTrustScore());
                    if (baseline.getNormalUserAgents() != null
                            && baseline.getNormalUserAgents().length > 0) {
                        ctx.setPreviousUserAgentBrowser(
                                baseline.getNormalUserAgents()[0]);
                    }
                }
            } catch (Exception e) {
                log.error("[Layer1] Failed to load baseline patterns for user {}: {}",
                        event.getUserId(), e.getMessage());
            }
        }

        enrichWithActivityContext(ctx, event);

        return ctx;
    }

    private void enrichWithActivityContext(
            SecurityPromptTemplate.BehaviorAnalysis ctx, SecurityEvent event) {
        if (dataStore == null || event.getUserId() == null) return;

        try {
            Long lastReqTime = dataStore.getLastRequestTime(event.getUserId());
            if (lastReqTime != null) {
                long interval = System.currentTimeMillis() - lastReqTime;
                ctx.setLastRequestIntervalMs(interval);
            }

            String prevPath = dataStore.getPreviousPath(event.getUserId());
            if (prevPath != null) {
                ctx.setPreviousPath(prevPath);
            }
        } catch (Exception e) {
            log.error("[Layer1] Failed to enrich activity context: {}",
                    e.getMessage());
        }
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
                .riskScore(0.7)
                .confidence(0.3)
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

    private class SessionContext extends BaseSessionContext {

        public void addEvent(SecurityEvent event) {
            accessFrequency++;

            int maxRecentActions = tieredStrategyProperties.getLayer1().getSession().getMaxRecentActions();
            if (recentActions.size() > maxRecentActions) {
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
    }

}