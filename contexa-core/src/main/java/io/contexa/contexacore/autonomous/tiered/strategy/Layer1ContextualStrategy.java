package io.contexa.contexacore.autonomous.tiered.strategy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Slf4j
public class Layer1ContextualStrategy extends AbstractTieredStrategy {

    // Layer1 only field
    private final SecurityDecisionPostProcessor postProcessor;
    private final Cache<String, SessionContext> sessionContextCache;

    @Value("${spring.ai.security.tiered.layer1.vector-search-limit:10}")
    private int vectorSearchLimit;

    public Layer1ContextualStrategy(UnifiedLLMOrchestrator llmOrchestrator,
                                    UnifiedVectorService unifiedVectorService,
                                    RedisTemplate<String, Object> redisTemplate,
                                    SecurityEventEnricher eventEnricher,
                                    SecurityPromptTemplate promptTemplate,
                                    BehaviorVectorService behaviorVectorService,
                                    BaselineLearningService baselineLearningService,
                                    SecurityDecisionPostProcessor postProcessor,
                                    TieredStrategyProperties tieredStrategyProperties) {
        super(llmOrchestrator, redisTemplate, eventEnricher, promptTemplate,
              behaviorVectorService, unifiedVectorService, baselineLearningService,
              tieredStrategyProperties);

        this.postProcessor = postProcessor;

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
        boolean shouldEscalate = decision.getAction() == SecurityDecision.Action.ESCALATE;
        String action = decision.getAction() != null ? decision.getAction().name() : "ESCALATE";

        return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessedAt(LocalDateTime.now())
                .riskScore(decision.getRiskScore())
                .confidence(decision.getConfidence())
                .indicators(new ArrayList<>())
                .recommendedActions(List.of(mapActionToRecommendation(decision.getAction())))
                .strategyName("Layer1-Contextual")
                .shouldEscalate(shouldEscalate)
                .action(action)
                .reasoning(decision.getReasoning())
                .build();
    }

    public SecurityDecision analyzeWithContext(SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        try {

            SessionContext sessionContext = buildSessionContext(event);

            List<Document> relatedDocuments = searchRelatedContext(event);
            List<String> similarEvents = extractSimilarEventsSummary(relatedDocuments);
            BaseBehaviorAnalysis behaviorAnalysis = analyzeBehaviorPatternsBase(event, baselineLearningService, similarEvents);

            SecurityPromptTemplate.SessionContext sessionCtx = convertToTemplateSessionContext(sessionContext);

            SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = convertToTemplateBehaviorAnalysis(behaviorAnalysis, event);

            String promptText = promptTemplate.buildPrompt(event, sessionCtx, behaviorCtx, relatedDocuments);

            long llmTimeoutMs = tieredStrategyProperties.getLayer1().getTimeout().getLlmMs();

            SecurityResponse response = null;
            if (llmOrchestrator != null) {

                ExecutionContext context = ExecutionContext.builder()
                        .prompt(new Prompt(promptText))
                        .tier(1)
                        .securityTaskType(ExecutionContext.SecurityTaskType.CONTEXTUAL_ANALYSIS)
                        .timeoutMs((int) llmTimeoutMs)
                        .requestId(event.getEventId())
                        .temperature(0.0)
                        .topP(1.0)
                        .build();

                String jsonResponse = llmOrchestrator.execute(context)
                        .timeout(Duration.ofMillis(llmTimeoutMs))
                        .onErrorResume(Exception.class, e -> {
                            log.warn("[Layer1][AI Native] LLM execution failed, escalating to Layer 2: {}", event.getEventId(), e);
                            return Mono.just("{\"riskScore\":null,\"confidence\":null,\"action\":\"ESCALATE\",\"reasoning\":\"[AI Native] LLM execution failed - escalating to Layer 2\",\"threatCategory\":\"UNKNOWN\"}");
                        })
                        .block();

                response = parseJsonResponse(jsonResponse);
            } else {
                log.warn("UnifiedLLMOrchestrator not available for Layer 1 analysis");
                response = createDefaultResponse();
            }

            SecurityDecision decision = convertToSecurityDecision(response, event);

            if (decision.getAction() == SecurityDecision.Action.ESCALATE) {
                Layer2ExpertStrategy.cachePromptContext(
                        event.getEventId(), sessionCtx, behaviorCtx, relatedDocuments);
            }

            enrichDecisionWithContext(decision, sessionContext, behaviorAnalysis);
            decision.setProcessingTimeMs(System.currentTimeMillis() - startTime);
            decision.setProcessingLayer(1);

            if (postProcessor != null) {
                postProcessor.updateSessionContext(event, decision);
            }

            if (postProcessor != null) {
                postProcessor.storeInVectorDatabase(event, decision);
            }

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

        // AI Native v12.0: Rule-based IP/UA change detection removed
        // LLM analyzes IP/UA changes via SecurityPromptTemplate (SIGNAL COMPARISON section)
        // Cache retained for session context reuse (performance optimization only)
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

        context.addEvent(event);

        if (sessionId != null && context.getUserId() != null) {
            sessionContextCache.put(sessionId, context);
        }

        return context;
    }

    private List<Document> searchRelatedContext(SecurityEvent event) {
        double similarityThreshold = tieredStrategyProperties.getLayer1().getRag().getSimilarityThreshold();
        int topK = Math.min(15, vectorSearchLimit * 2);
        return searchRelatedContextBase(event, topK, similarityThreshold);
    }

    private SecurityPromptTemplate.SessionContext convertToTemplateSessionContext(SessionContext sessionContext) {
        SecurityPromptTemplate.SessionContext ctx = new SecurityPromptTemplate.SessionContext();
        ctx.setSessionId(sessionContext.getSessionId());
        ctx.setUserId(sessionContext.getUserId());
        ctx.setAuthMethod(sessionContext.getAuthMethod());
        ctx.setRecentActions(sessionContext.getRecentActions());

        if (sessionContext.getStartTime() != null) {
            long minutes = java.time.Duration.between(
                    sessionContext.getStartTime(),
                    java.time.LocalDateTime.now()
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

        if (event != null && event.getUserAgent() != null) {
            String currentOS = extractOSFromUserAgent(event.getUserAgent());
            ctx.setCurrentUserAgentOS(currentOS);
        }

        if (behaviorAnalysis.getBaselineContext() != null) {
            String baselineOS = extractOSFromBaselineContext(behaviorAnalysis.getBaselineContext());
            ctx.setPreviousUserAgentOS(baselineOS);
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
        }

        return null;
    }

    private SecurityDecision convertToSecurityDecision(SecurityResponse response,
                                                       SecurityEvent event) {
        SecurityDecision.Action action = mapStringToAction(response.getAction());

        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(response.getRiskScore() != null ? response.getRiskScore() : Double.NaN)
                .confidence(response.getConfidence() != null ? response.getConfidence() : Double.NaN)
                .reasoning(response.getReasoning())
                .eventId(event.getEventId())
                .analysisTime(System.currentTimeMillis())
                .build();

        if (response.getMitre() != null && !response.getMitre().isBlank()) {
            decision.setThreatCategory(response.getMitre());
        }

        return decision;
    }

    private SecurityResponse parseJsonResponse(String jsonResponse) {
        try {

            String cleanedJson = extractJsonObject(jsonResponse);

            SecurityResponse response = SecurityResponse.fromJson(cleanedJson);

            if (response != null && response.isValid()) {
                return validateAndFixResponse(response);
            }

            log.warn("[Layer1] JSON 파싱 실패, 기본 응답 반환: {}", cleanedJson);
            return createDefaultResponse();

        } catch (Exception e) {
            log.error("[Layer1] JSON 응답 파싱 실패: {}", jsonResponse, e);
            return createDefaultResponse();
        }
    }

    private SecurityResponse createDefaultResponse() {
        return SecurityResponse.builder()
                .riskScore(null)
                .confidence(null)
                .action("ESCALATE")
                .reasoning("[AI Native] Layer 1 LLM analysis unavailable - escalating to Layer 2")
                .mitre(null)
                .build();
    }

    private void enrichDecisionWithContext(SecurityDecision decision,
                                           SessionContext sessionContext,
                                           BaseBehaviorAnalysis behaviorAnalysis) {

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

    private SecurityDecision createFallbackDecision(long startTime) {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ESCALATE)
                .riskScore(Double.NaN)
                .confidence(Double.NaN)
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

    public List<String> getRecommendedActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        actions.add("ANALYZE_SESSION_CONTEXT");
        actions.add("CHECK_BEHAVIOR_BASELINE");
        return actions;
    }

    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        return Double.NaN;
    }

    private String mapActionToRecommendation(SecurityDecision.Action action) {
        return switch (action) {
            case ALLOW -> "ALLOW";
            case BLOCK -> "BLOCK_IMMEDIATELY";
            case CHALLENGE -> "REQUIRE_MFA";
            case ESCALATE -> "ESCALATE_TO_EXPERT";
        };
    }

    private class SessionContext extends BaseSessionContext {

        public void addEvent(SecurityEvent event) {
            accessFrequency++;

            int maxRecentActions = tieredStrategyProperties.getLayer1().getSession().getMaxRecentActions();
            if (recentActions.size() > maxRecentActions) {
                recentActions.removeFirst();
            }

            recentActions.add(event.getDescription() != null ? event.getDescription() : "action");
        }
    }

    private SecurityResponse validateAndFixResponse(SecurityResponse response) {
        if (response == null) {
            return createDefaultResponse();
        }

        double[] validated = validateResponseBase(response.getRiskScore(), response.getConfidence());
        response.setRiskScore(validated[0]);
        response.setConfidence(validated[1]);

        if (response.getAction() == null || response.getAction().isBlank()) {
            response.setAction("ESCALATE");
        }

        return response;
    }

}