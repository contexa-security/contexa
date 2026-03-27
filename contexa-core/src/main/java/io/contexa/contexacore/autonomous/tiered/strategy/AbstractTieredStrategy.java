package io.contexa.contexacore.autonomous.tiered.strategy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.DefaultPromptConfidenceGuardrail;
import io.contexa.contexacore.autonomous.context.PromptConfidenceGuardrail;
import io.contexa.contexacore.autonomous.context.PromptDecisionAdjustment;
import io.contexa.contexacore.autonomous.context.ProposedPromptDecision;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditForwardingService;
import io.contexa.contexacore.autonomous.saas.SaasBaselineSeedService;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
public abstract class AbstractTieredStrategy implements ThreatEvaluationStrategy {

    protected static final PipelineConfiguration SECURITY_DECISION_PIPELINE_CONFIGURATION =
            PipelineConfiguration.builder()
                    .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                    .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                    .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                    .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                    .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                    .timeoutSeconds(120)
                    .build();

    protected final UnifiedLLMOrchestrator llmOrchestrator;
    protected final SecurityEventEnricher eventEnricher;
    protected final SecurityDecisionStandardPromptTemplate promptTemplate;
    protected final BehaviorVectorService behaviorVectorService;
    protected final UnifiedVectorService unifiedVectorService;
    protected final BaselineLearningService baselineLearningService;
    protected final TieredStrategyProperties tieredStrategyProperties;
    protected final PromptContextAuthorizationService promptContextAuthorizationService;
    protected final PromptContextAuditForwardingService promptContextAuditForwardingService;
    protected final PromptConfidenceGuardrail promptConfidenceGuardrail;
    private static final Cache<String, SecurityDecisionStandardPromptTemplate.SessionContext> ESCALATION_SESSION_CACHE =
            Caffeine.newBuilder()
                    .maximumSize(1000)
                    .expireAfterWrite(30, TimeUnit.MINUTES)
                    .build();

    private static final Cache<String, SecurityDecisionStandardPromptTemplate.BehaviorAnalysis> ESCALATION_BEHAVIOR_CACHE =
            Caffeine.newBuilder()
                    .maximumSize(1000)
                    .expireAfterWrite(30, TimeUnit.MINUTES)
                    .build();

    private static final Cache<String, List<Document>> ESCALATION_RAG_CACHE =
            Caffeine.newBuilder()
                    .maximumSize(500)
                    .expireAfterWrite(30, TimeUnit.MINUTES)
                    .build();

    protected AbstractTieredStrategy(
            UnifiedLLMOrchestrator llmOrchestrator,
            SecurityEventEnricher eventEnricher,
            SecurityDecisionStandardPromptTemplate promptTemplate,
            BehaviorVectorService behaviorVectorService,
            UnifiedVectorService unifiedVectorService,
            BaselineLearningService baselineLearningService,
            PromptContextAuthorizationService promptContextAuthorizationService,
            PromptContextAuditForwardingService promptContextAuditForwardingService,
            TieredStrategyProperties tieredStrategyProperties) {
        this.llmOrchestrator = llmOrchestrator;
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.promptTemplate = promptTemplate != null ? promptTemplate
            : new SecurityDecisionStandardPromptTemplate(this.eventEnricher, tieredStrategyProperties);
        this.behaviorVectorService = behaviorVectorService;
        this.unifiedVectorService = unifiedVectorService;
        this.baselineLearningService = baselineLearningService;
        this.tieredStrategyProperties = tieredStrategyProperties;
        this.promptContextAuthorizationService = promptContextAuthorizationService != null
                ? promptContextAuthorizationService
                : new PromptContextAuthorizationService();
        this.promptContextAuditForwardingService = promptContextAuditForwardingService;
        this.promptConfidenceGuardrail = new DefaultPromptConfidenceGuardrail();
    }

    protected abstract String getLayerName();

    @Override
    public String getStrategyName() {
        return getLayerName();
    }

    protected String getContextRetrievalPurpose() {
        return getLayerName().toLowerCase(Locale.ROOT) + "_security_investigation";
    }

    protected static void cacheEscalationContext(String eventId,
                                                  SecurityDecisionStandardPromptTemplate.SessionContext sessionCtx,
                                                  SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorCtx,
                                                  List<Document> ragDocuments) {
        if (eventId == null) return;
        if (sessionCtx != null) ESCALATION_SESSION_CACHE.put(eventId, sessionCtx);
        if (behaviorCtx != null) ESCALATION_BEHAVIOR_CACHE.put(eventId, behaviorCtx);
        if (ragDocuments != null && !ragDocuments.isEmpty()) ESCALATION_RAG_CACHE.put(eventId, ragDocuments);
    }

    protected static SecurityDecisionStandardPromptTemplate.SessionContext getCachedSessionContext(String eventId) {
        return eventId != null ? ESCALATION_SESSION_CACHE.getIfPresent(eventId) : null;
    }

    protected static SecurityDecisionStandardPromptTemplate.BehaviorAnalysis getCachedBehaviorAnalysis(String eventId) {
        return eventId != null ? ESCALATION_BEHAVIOR_CACHE.getIfPresent(eventId) : null;
    }

    protected static List<Document> getCachedRagDocuments(String eventId) {
        return eventId != null ? ESCALATION_RAG_CACHE.getIfPresent(eventId) : null;
    }

    protected SecurityResponse parseJsonResponse(String jsonResponse) {
        try {
            String cleanedJson = extractJsonObject(jsonResponse);
            SecurityResponse response = SecurityResponse.fromJson(cleanedJson);
            if (response != null && response.isValid()) {
                return validateAndFixResponse(response);
            }
            log.error("[{}] JSON parsing failed, returning default response", getLayerName());
            return createDefaultResponse();
        } catch (Exception e) {
            log.error("[{}] JSON response parsing failed", getLayerName(), e);
            return createDefaultResponse();
        }
    }

    protected SecurityResponse validateAndFixResponse(SecurityResponse response) {
        if (response == null) return createDefaultResponse();
        response.setRiskScore(normalizeOptionalScore(response.getRiskScore()));
        response.setConfidence(normalizeOptionalScore(response.getConfidence()));
        if (response.getAction() != null && !response.getAction().isBlank()) {
            ZeroTrustAction mapped = ZeroTrustAction.fromString(response.getAction());
            response.setAction(mapped.name());
        } else {
            response.setAction(ZeroTrustAction.ESCALATE.name());
        }
        return response;
    }

    protected SecurityResponse createDefaultResponse() {
        return SecurityResponse.builder()
                .riskScore(null)
                .confidence(null)
                .action(ZeroTrustAction.ESCALATE.name())
                .reasoning("[AI Native] " + getLayerName() + " LLM analysis unavailable")
                .mitre(null)
                .build();
    }

    protected SecurityDecision convertToSecurityDecisionBase(SecurityResponse response, SecurityEvent event) {
        if (response == null) response = createDefaultResponse();
        ZeroTrustAction action = mapStringToAction(response.getAction());
        SecurityDecision decision = SecurityDecision.builder()
                .action(action)
                .riskScore(null)
                .confidence(null)
                .llmAuditRiskScore(normalizeOptionalScore(response.getRiskScore()))
                .llmAuditConfidence(normalizeOptionalScore(response.getConfidence()))
                .reasoning(response.getReasoning())
                .eventId(event != null ? event.getEventId() : "unknown")
                .analysisTime(System.currentTimeMillis())
                .build();
        if (response.getMitre() != null && !response.getMitre().isBlank()) {
            decision.setThreatCategory(response.getMitre());
        }
        return decision;
    }

    protected List<String> extractSimilarEventsSummary(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return Collections.emptyList();
        }

        return documents.stream()
                .limit(5)
                .map(doc -> {
                    Map<String, Object> meta = doc.getMetadata();

                    StringBuilder summary = new StringBuilder();
                    Object docType = meta.get("documentType");
                    if ("threat".equals(String.valueOf(docType))) {
                        summary.append("[BLOCKED] ");
                    } else {
                        summary.append("[HISTORICAL] ");
                    }

                    appendMetaIfPresent(summary, meta, "sourceIp", "IP");
                    appendMetaIfPresent(summary, meta, "requestPath", "Path");
                    appendMetaIfPresent(summary, meta, "hour", "Hour");
                    appendMetaIfPresent(summary, meta, "userAgentOS", "OS");
                    appendMetaIfPresent(summary, meta, "userAgentBrowser", "UA");

                    String content = doc.getText();
                    if (content != null && !content.isBlank()) {
                        String truncated = content.length() > 120
                                ? content.substring(0, 120) + "..."
                                : content;
                        summary.append(" -> ").append(truncated);
                    }

                    return summary.toString();
                })
                .collect(Collectors.toList());
    }

    protected static double extractSimilarityScore(Document doc) {
        Double docScore = doc.getScore();
        if (docScore != null) {
            return docScore;
        }
        Map<String, Object> meta = doc.getMetadata();
        Object scoreObj = meta.get(VectorDocumentMetadata.SIMILARITY_SCORE);
        if (scoreObj == null) scoreObj = meta.get("score");
        if (scoreObj == null) scoreObj = meta.get("distance");
        if (scoreObj instanceof Number) {
            return ((Number) scoreObj).doubleValue();
        }
        return 0.0;
    }

    private static void appendMetaIfPresent(StringBuilder sb, Map<String, Object> meta,
                                             String key, String label) {
        Object val = meta.get(key);
        if (val != null && !val.toString().isEmpty()) {
            sb.append(", ").append(label).append(":").append(val);
        }
    }

    protected ZeroTrustAction mapStringToAction(String action) {
        ZeroTrustAction zta = ZeroTrustAction.fromString(action);
        if (zta == ZeroTrustAction.ESCALATE && action != null && !action.isBlank()) {
            String upper = action.trim().toUpperCase();
            if (!ZeroTrustAction.ESCALATE.name().equals(upper) && !"E".equals(upper)) {
                log.error("[{}] Unknown action '{}' from LLM, converting to ESCALATE",
                        getLayerName(), action);
            }
        }
        return zta;
    }

    protected Double normalizeOptionalScore(Double value) {
        if (value == null || !Double.isFinite(value)) {
            return null;
        }
        return Math.max(0.0, Math.min(1.0, value));
    }

    protected SecurityDecision applyPromptConfidenceGuardrail(SecurityDecision decision, SecurityEvent event) {
        if (decision == null) {
            return null;
        }

        CanonicalSecurityContext canonicalContext = resolveCanonicalContext(event).orElse(null);
        PromptDecisionAdjustment adjustment = promptConfidenceGuardrail.evaluate(
                canonicalContext,
                ProposedPromptDecision.from(decision)
        );

        decision.setConfidence(adjustment.effectiveConfidence());
        decision.setAutonomyConstraintApplied(adjustment.applied());
        decision.setAutonomyConstraintReasons(adjustment.reasons());
        decision.setAutonomyConstraintSummary(adjustment.summary());
        decision.setAutonomousAction(adjustment.enforcementAction());
        return decision;
    }

    private Optional<CanonicalSecurityContext> resolveCanonicalContext(SecurityEvent event) {
        if (event == null || promptTemplate == null) {
            return Optional.empty();
        }
        return promptTemplate.resolveCanonicalSecurityContextForGuardrail(event);
    }

    protected BaseBehaviorAnalysis analyzeBehaviorPatternsBase(SecurityEvent event,
                                                                 BaselineLearningService baselineLearningService,
                                                                 List<String> similarEvents) {
        BaseBehaviorAnalysis analysis = new BaseBehaviorAnalysis();
        String userId = event.getUserId();
        analysis.setSimilarEvents(similarEvents != null ? similarEvents : Collections.emptyList());
        if (baselineLearningService == null) {
            analysis.setBaselineContext("[SERVICE_UNAVAILABLE] Baseline learning service not configured");
            analysis.setBaselineEstablished(false);
        } else if (userId == null) {
            log.error("[{}][SYSTEM_ERROR] userId is null - authentication system failure", getLayerName());
            analysis.setBaselineContext("[SYSTEM_ERROR] Authentication failure - userId unavailable. " +
                "This should not happen in authenticated platform. Recommend ESCALATE.");
            analysis.setBaselineEstablished(false);
        } else {
            try {
                String baselineContext = baselineLearningService.buildBaselinePromptContext(userId, event);

                if (baselineContext == null || baselineContext.isEmpty()) {
                    analysis.setBaselineContext("[NO_DATA] Baseline service returned empty response");
                } else {
                    analysis.setBaselineContext(baselineContext);
                }
                analysis.setBaselineEstablished(baselineLearningService.getBaseline(userId) != null);

            } catch (Exception e) {
                log.error("[{}] Baseline service error for user {}: {}", getLayerName(), userId, e.getMessage());
                analysis.setBaselineContext("[SERVICE_ERROR] Baseline service error: " + e.getMessage());
                analysis.setBaselineEstablished(false);
            }
        }

        return analysis;
    }

    protected void annotateThreatKnowledgeContext(
            SecurityEvent event,
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        if (event == null || behaviorAnalysis == null) {
            return;
        }
        ThreatKnowledgePackMatchContext matchContext = behaviorAnalysis.getThreatKnowledgePackMatchContext();
        if (matchContext == null || !matchContext.hasMatches()) {
            event.addMetadata("threatKnowledgeApplied", false);
            event.addMetadata("reasoningMemoryApplied", false);
            event.addMetadata("threatKnowledgeExperimentGroup", "BASELINE_ONLY");
            return;
        }

        List<String> knowledgeKeys = matchContext.matchedCases().stream()
                .map(ThreatKnowledgePackMatchContext.MatchedKnowledgeCase::knowledgeCase)
                .filter(Objects::nonNull)
                .map(item -> item.knowledgeKey() != null ? item.knowledgeKey() : item.signalKey())
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        List<String> signalKeys = matchContext.matchedCases().stream()
                .map(ThreatKnowledgePackMatchContext.MatchedKnowledgeCase::knowledgeCase)
                .filter(Objects::nonNull)
                .map(item -> item.signalKey())
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        List<String> matchedFacts = matchContext.matchedCases().stream()
                .flatMap(item -> item.matchedFacts().stream())
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(text -> !text.isBlank())
                .distinct()
                .limit(8)
                .toList();
        boolean reasoningMemoryApplied = matchContext.matchedCases().stream()
                .map(ThreatKnowledgePackMatchContext.MatchedKnowledgeCase::knowledgeCase)
                .filter(Objects::nonNull)
                .anyMatch(item -> item.reasoningMemoryFacts() != null && !item.reasoningMemoryFacts().isEmpty()
                        || item.reasoningMemoryStatus() != null && !"COLLECTING".equalsIgnoreCase(item.reasoningMemoryStatus()));

        event.addMetadata("threatKnowledgeApplied", true);
        event.addMetadata("reasoningMemoryApplied", reasoningMemoryApplied);
        event.addMetadata("threatKnowledgeExperimentGroup", "KNOWLEDGE_ASSISTED");
        event.addMetadata("threatKnowledgeCaseCount", knowledgeKeys.size());
        if (!knowledgeKeys.isEmpty()) {
            event.addMetadata("threatKnowledgePrimaryKey", knowledgeKeys.get(0));
            event.addMetadata("threatKnowledgeKeys", knowledgeKeys);
        }
        if (!signalKeys.isEmpty()) {
            event.addMetadata("threatKnowledgeSignalKeys", signalKeys);
        }
        if (!matchedFacts.isEmpty()) {
            event.addMetadata("threatKnowledgeMatchedFacts", matchedFacts);
        }
    }
    protected void enrichBehaviorAnalysisWithBaselineSupport(
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis context,
            SecurityEvent event,
            SaasBaselineSeedService baselineSeedService) {
        if (context == null || event == null || event.getUserId() == null || baselineLearningService == null) {
            return;
        }
        event.addMetadata("baselineSeedApplied", false);
        event.addMetadata("personalBaselineEstablished", false);
        event.addMetadata("organizationBaselineEstablished", false);

        try {
            BaselineVector baseline = baselineLearningService.getBaseline(event.getUserId());
            if (baseline != null) {
                context.setBaselineIpRanges(baseline.getNormalIpRanges());
                context.setBaselineOperatingSystems(baseline.getNormalOperatingSystems());
                context.setBaselineUserAgents(baseline.getNormalUserAgents());
                context.setBaselineFrequentPaths(baseline.getFrequentPaths());
                context.setBaselineAccessHours(baseline.getNormalAccessHours());
                context.setBaselineAccessDays(baseline.getNormalAccessDays());
                context.setBaselineUpdateCount(baseline.getUpdateCount());
                context.setBaselineAvgTrustScore(baseline.getAvgTrustScore());
                if (baseline.getNormalUserAgents() != null && baseline.getNormalUserAgents().length > 0) {
                    context.setPreviousUserAgentBrowser(baseline.getNormalUserAgents()[0]);
                }
            }

            BaselineLearningService.BaselineMaturitySnapshot maturity =
                    baselineLearningService.describeBaselineMaturity(event.getUserId());
            if (maturity == null) {
                return;
            }

            context.setPersonalBaselineAvailable(maturity.personalBaselineAvailable());
            context.setPersonalBaselineEstablished(maturity.personalBaselineEstablished());
            context.setOrganizationBaselineAvailable(maturity.organizationBaselineAvailable());
            context.setOrganizationBaselineEstablished(maturity.organizationBaselineEstablished());
            event.addMetadata("personalBaselineEstablished", maturity.personalBaselineEstablished());
            event.addMetadata("organizationBaselineEstablished", maturity.organizationBaselineEstablished());
            context.setCohortSeedRecommended(maturity.cohortSeedRecommended());
            context.setCohortSeedSupportingDimensions(maturity.supportingDimensions());

            if (!maturity.cohortSeedRecommended() || baselineSeedService == null) {
                return;
            }

            BaselineSeedSnapshot baselineSeed = baselineSeedService.getPromptSeed();
            if (baselineSeed == null || !baselineSeed.featureEnabled() || !baselineSeed.seedAvailable()) {
                return;
            }

            context.setCohortBaselineSeed(baselineSeed);
            context.setCohortSeedApplied(true);
            event.addMetadata("baselineSeedApplied", true);
        } catch (Exception ex) {
            log.error("[{}] Failed to enrich baseline support context for user {}",
                    getLayerName(), event.getUserId(), ex);
        }
    }

    protected List<Document> searchRelatedContextBase(SecurityEvent event,
                                                       int topK,
                                                       double similarityThreshold) {
        if (unifiedVectorService == null) {
            return Collections.emptyList();
        }
        try {
            StringBuilder queryBuilder = new StringBuilder();

            if (event.getSourceIp() != null) {
                queryBuilder.append("IP: ").append(event.getSourceIp());
            }

            String targetResource = eventEnricher.getTargetResource(event).orElse(null);
            if (targetResource != null && !targetResource.isEmpty()) {
                if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                queryBuilder.append("Path: ").append(targetResource);
            }

            String currentOS = SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent());
            if (currentOS != null && !"Desktop".equals(currentOS)) {
                if (!queryBuilder.isEmpty()) queryBuilder.append(", ");
                queryBuilder.append("OS: ").append(currentOS);
            }

            String query = queryBuilder.toString().trim();
            if (query.isEmpty()) {
                return Collections.emptyList();
            }

            String userId = event.getUserId();
            if (userId == null || userId.isEmpty() || "unknown".equals(userId)) {
                log.error("[{}] userId missing - skipping RAG search for account isolation",
                    getLayerName());
                return Collections.emptyList();
            }

            FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
            Filter.Expression filter = filterBuilder.and(
                filterBuilder.or(
                    filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()),
                    filterBuilder.eq("documentType", VectorDocumentType.THREAT.getValue())
                ),
                filterBuilder.eq("userId", userId)
            ).build();

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(topK)
                    .similarityThreshold(similarityThreshold)
                    .filterExpression(filter)
                    .build();

            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);
            if (documents == null || documents.isEmpty()) {
                return Collections.emptyList();
            }

            AuthorizedPromptContext authorizedPromptContext = promptContextAuthorizationService
                    .authorize(event, getContextRetrievalPurpose(), documents);
            if (promptContextAuditForwardingService != null) {
                promptContextAuditForwardingService.capture(
                        event,
                        getContextRetrievalPurpose(),
                        authorizedPromptContext);
            }
            return authorizedPromptContext.documents();

        } catch (Exception e) {
            log.error("[{}] Vector store context search failed", getLayerName(), e);
            return Collections.emptyList();
        }
    }

    protected static class BaseSessionContext {
        protected String sessionId;
        protected String userId;
        protected String authMethod;
        protected LocalDateTime startTime;
        protected String ipAddress;
        protected String userAgent;
        protected List<String> recentActions = new ArrayList<>();
        protected int accessFrequency = 0;

        public boolean isValid() {
            return startTime != null;
        }

        public long getSessionDuration() {
            if (startTime == null) return 0;
            return Duration.between(startTime, LocalDateTime.now()).toMinutes();
        }

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }

        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

        public List<String> getRecentActions() { return recentActions; }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        public int getAccessFrequency() { return accessFrequency; }
        public void setAccessFrequency(int accessFrequency) { this.accessFrequency = accessFrequency; }
    }


    protected static class BaseBehaviorAnalysis {
        protected List<String> similarEvents = new ArrayList<>();
        protected String baselineContext;
        protected boolean baselineEstablished;

        public List<String> getSimilarEvents() { return similarEvents; }
        public void setSimilarEvents(List<String> events) { this.similarEvents = events; }

        public String getBaselineContext() { return baselineContext; }
        public void setBaselineContext(String baselineContext) { this.baselineContext = baselineContext; }

        public boolean isBaselineEstablished() { return baselineEstablished; }
        public void setBaselineEstablished(boolean baselineEstablished) { this.baselineEstablished = baselineEstablished; }
    }


    protected String extractJsonObject(String response) {
        if (response == null || response.isEmpty()) {
            return "{}";
        }

        int startIndex = response.indexOf('{');
        if (startIndex == -1) {
            return response;
        }

        int braceCount = 0;
        int endIndex = -1;
        boolean inString = false;
        boolean escaped = false;

        for (int i = startIndex; i < response.length(); i++) {
            char c = response.charAt(i);

            if (escaped) {
                escaped = false;
                continue;
            }

            if (c == '\\') {
                escaped = true;
                continue;
            }

            if (c == '"') {
                inString = !inString;
                continue;
            }

            if (!inString) {
                if (c == '{') {
                    braceCount++;
                } else if (c == '}') {
                    braceCount--;
                    if (braceCount == 0) {
                        endIndex = i;
                        break;
                    }
                }
            }
        }
        if (endIndex != -1) {
            return response.substring(startIndex, endIndex + 1);
        }
        endIndex = response.lastIndexOf('}');
        if (endIndex > startIndex) {
            return response.substring(startIndex, endIndex + 1);
        }
        return response;
    }

    protected Map<String, Object> buildAnalysisContext(SecurityDecisionStandardPromptTemplate.SessionContext sessionCtx,
                                                       SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorCtx, List<Document> relatedDocuments) {
        Map<String, Object> context = new HashMap<>();
        if (sessionCtx != null) {
            context.put("sessionContext", sessionCtx);
        }
        if (behaviorCtx != null) {
            context.put("behaviorAnalysis", behaviorCtx);
        }
        if (relatedDocuments != null && !relatedDocuments.isEmpty()) {
            context.put("relatedDocuments", relatedDocuments);
        }
        return context;
    }

    protected SecurityDecisionRequest buildSecurityDecisionRequest(
            SecurityEvent event,
            SecurityDecisionStandardPromptTemplate.SessionContext sessionContext,
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments) {
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        behaviorAnalysis,
                        relatedDocuments
                ));
        request.withParameter("responseType", SecurityDecisionResponse.class);
        request.withParameter("promptBudgetProfile", resolvePromptBudgetProfile().profileKey());
        return request;
    }

    protected PromptBudgetProfile resolvePromptBudgetProfile() {
        String layerName = getLayerName();
        if (layerName != null && layerName.toLowerCase(Locale.ROOT).contains("layer2")) {
            return PromptBudgetProfile.CORTEX_L2_STANDARD;
        }
        return PromptBudgetProfile.CORTEX_L1_STANDARD;
    }

    protected void clearPromptRuntimeTelemetry(SecurityEvent event) {
        if (event == null) {
            return;
        }
        Map<String, Object> metadata = ensureMutableEventMetadata(event);
        for (String key : PromptRuntimeTelemetrySupport.runtimeTelemetryKeys()) {
            metadata.remove(key);
        }
        metadata.remove("promptRuntimeTelemetryLinked");
        metadata.remove("promptRuntimeTelemetryLayer");
    }

    protected void capturePromptRuntimeTelemetry(SecurityEvent event, SecurityDecisionResponse pipelineResponse) {
        if (event == null || pipelineResponse == null) {
            return;
        }
        Map<String, Object> telemetry = PromptRuntimeTelemetrySupport.extractRuntimeTelemetry(
                pipelineResponse.getAllMetadata());
        if (telemetry.isEmpty()) {
            return;
        }
        Map<String, Object> metadata = ensureMutableEventMetadata(event);
        telemetry.forEach(metadata::put);
        metadata.put("promptRuntimeTelemetryLinked", true);
        metadata.put("promptRuntimeTelemetryLayer", getLayerName());
    }

    private Map<String, Object> ensureMutableEventMetadata(SecurityEvent event) {
        Map<String, Object> current = event.getMetadata();
        if (current == null) {
            Map<String, Object> fresh = new LinkedHashMap<>();
            event.setMetadata(fresh);
            return fresh;
        }
        if (current instanceof LinkedHashMap || current instanceof HashMap) {
            return current;
        }
        Map<String, Object> copied = new LinkedHashMap<>(current);
        event.setMetadata(copied);
        return copied;
    }

    protected Mono<SecurityDecisionResponse> executeSecurityDecisionPipeline(
            PipelineOrchestrator pipelineOrchestrator,
            SecurityEvent event,
            SecurityDecisionStandardPromptTemplate.SessionContext sessionContext,
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments) {
        if (pipelineOrchestrator == null) {
            return Mono.error(new IllegalStateException("PipelineOrchestrator not available"));
        }
        return pipelineOrchestrator.execute(
                buildSecurityDecisionRequest(event, sessionContext, behaviorAnalysis, relatedDocuments),
                SECURITY_DECISION_PIPELINE_CONFIGURATION,
                SecurityDecisionResponse.class);
    }
}









