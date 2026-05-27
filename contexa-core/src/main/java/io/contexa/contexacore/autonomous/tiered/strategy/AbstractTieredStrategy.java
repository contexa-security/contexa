package io.contexa.contexacore.autonomous.tiered.strategy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditForwardingService;
import io.contexa.contexacore.autonomous.saas.SaasBaselineSeedService;
import io.contexa.contexacore.autonomous.saas.SaasDetectionStrategyPackService;
import io.contexa.contexacore.autonomous.saas.SaasThreatIntelligenceService;
import io.contexa.contexacore.autonomous.saas.SaasThreatKnowledgePackService;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.saas.learning.cohort.CohortSeedRuntimeWeightDecision;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
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
import io.contexa.contexacore.std.llm.client.StructuredOutputCapability;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineFailurePolicy;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.step.StructuredOutputExecutionException;
import io.contexa.contexacore.std.pipeline.step.StructuredOutputPolicy;
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
import org.springframework.util.StringUtils;
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

    protected final SecurityEventEnricher eventEnricher;
    protected final SecurityDecisionStandardPromptTemplate promptTemplate;
    protected final BehaviorVectorService behaviorVectorService;
    protected final UnifiedVectorService unifiedVectorService;
    protected final BaselineLearningService baselineLearningService;
    protected final TieredStrategyProperties tieredStrategyProperties;
    protected final PromptContextAuthorizationService promptContextAuthorizationService;
    protected final PromptContextAuditForwardingService promptContextAuditForwardingService;
    protected final StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry;
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
            SecurityEventEnricher eventEnricher,
            SecurityDecisionStandardPromptTemplate promptTemplate,
            BehaviorVectorService behaviorVectorService,
            UnifiedVectorService unifiedVectorService,
            BaselineLearningService baselineLearningService,
            PromptContextAuthorizationService promptContextAuthorizationService,
            PromptContextAuditForwardingService promptContextAuditForwardingService,
            TieredStrategyProperties tieredStrategyProperties) {
        this(
                eventEnricher,
                promptTemplate,
                behaviorVectorService,
                unifiedVectorService,
                baselineLearningService,
                promptContextAuthorizationService,
                promptContextAuditForwardingService,
                tieredStrategyProperties,
                StructuredOutputCapabilityRegistry.defaultRegistry());
    }

    protected AbstractTieredStrategy(
            SecurityEventEnricher eventEnricher,
            SecurityDecisionStandardPromptTemplate promptTemplate,
            BehaviorVectorService behaviorVectorService,
            UnifiedVectorService unifiedVectorService,
            BaselineLearningService baselineLearningService,
            PromptContextAuthorizationService promptContextAuthorizationService,
            PromptContextAuditForwardingService promptContextAuditForwardingService,
            TieredStrategyProperties tieredStrategyProperties,
            StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry) {
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
        this.structuredOutputCapabilityRegistry = structuredOutputCapabilityRegistry != null
                ? structuredOutputCapabilityRegistry
                : StructuredOutputCapabilityRegistry.defaultRegistry();
    }

    protected abstract String getLayerName();

    @Override
    public String getStrategyName() {
        return getLayerName();
    }

    protected String getContextRetrievalPurpose() {
        return "security_investigation";
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

    protected SecurityDecision createTechnicalFallbackDecision(
            SecurityEvent event,
            ZeroTrustAction fallbackAction,
            String fallbackReason,
            String fallbackCategory,
            long startTime,
            int processingLayer) {
        return createTechnicalFallbackDecision(
                event,
                fallbackAction,
                fallbackReason,
                fallbackCategory,
                startTime,
                processingLayer,
                false,
                null);
    }

    protected SecurityDecision createTechnicalFallbackDecision(
            SecurityEvent event,
            ZeroTrustAction fallbackAction,
            String fallbackReason,
            String fallbackCategory,
            long startTime,
            int processingLayer,
            boolean requiresApproval,
            String expertRecommendation) {
        return SecurityDecision.builder()
                .action(fallbackAction)
                .autonomousAction(fallbackAction)
                .llmDecisionPresent(false)
                .technicalFallbackApplied(true)
                .technicalFallbackCategory(fallbackCategory)
                .technicalFallbackReason(fallbackReason)
                .technicalFallbackAction(fallbackAction != null ? fallbackAction.name() : null)
                .analysisTime(startTime)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .processingLayer(processingLayer)
                .eventId(event != null ? event.getEventId() : "unknown")
                .reasoning(fallbackReason)
                .requiresApproval(requiresApproval)
                .expertRecommendation(expertRecommendation)
                .build();
    }

    protected String resolveTechnicalFailureCategory(Throwable throwable) {
        if (throwable == null) {
            return "UNKNOWN";
        }
        if (throwable instanceof StructuredOutputExecutionException structuredOutputExecutionException) {
            return structuredOutputExecutionException.getCategory().name();
        }
        return throwable.getClass().getSimpleName();
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

    protected BaseBehaviorAnalysis analyzeBehaviorPatternsBase(SecurityEvent event,
                                                                 BaselineLearningService baselineLearningService,
                                                                 List<String> similarEvents) {
        BaseBehaviorAnalysis analysis = new BaseBehaviorAnalysis();
        String userId = event.getUserId();
        analysis.setSimilarEvents(similarEvents != null ? similarEvents : Collections.emptyList());
        if (baselineLearningService == null) {
            analysis.setBaselineEstablished(false);
        } else if (userId == null) {
            log.error("[{}][SYSTEM_ERROR] userId is null - authentication system failure", getLayerName());
            analysis.setBaselineEstablished(false);
        } else {
            try {
                analysis.setBaselineEstablished(baselineLearningService.getPersonalBaseline(userId) != null);

            } catch (Exception e) {
                log.error("[{}] Baseline service error for user {}: {}", getLayerName(), userId, e.getMessage());
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
    protected void enrichBehaviorAnalysisWithRuntimeLearningSupport(
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis context,
            SecurityEvent event,
            SaasBaselineSeedService baselineSeedService,
            SaasThreatIntelligenceService threatIntelligenceService,
            SaasThreatKnowledgePackService threatKnowledgePackService,
            SaasDetectionStrategyPackService detectionStrategyPackService) {
        if (context == null || event == null) {
            return;
        }

        if (threatIntelligenceService != null) {
            context.setActiveThreatSignals(threatIntelligenceService.getPromptSignals());
        }
        if (threatKnowledgePackService != null) {
            context.setThreatKnowledgePack(threatKnowledgePackService.currentSnapshot());
        }
        if (detectionStrategyPackService != null) {
            context.setDetectionStrategyPack(detectionStrategyPackService.currentSnapshot());
            context.setDetectionStrategyRuntimePack(detectionStrategyPackService.getPromptRuntimePack());
        }

        enrichBehaviorAnalysisWithBaselineSupport(context, event, baselineSeedService);
        hydrateBehaviorAnalysisRuntimeFacts(context, event);

        if (threatIntelligenceService != null) {
            context.setThreatIntelligenceMatchContext(threatIntelligenceService.buildThreatContext(event, context));
        }
        if (threatKnowledgePackService != null) {
            context.setThreatKnowledgePackMatchContext(
                    threatKnowledgePackService.buildThreatKnowledgeContext(event, context));
        }
    }
    protected void enrichBehaviorAnalysisWithBaselineSupport(
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis context,
            SecurityEvent event,
            SaasBaselineSeedService baselineSeedService) {
        if (context == null || event == null) {
            return;
        }
        if (baselineLearningService == null) {
            applyUnavailableBaselineEvidence(
                    context,
                    BaselineEvidenceStatus.SERVICE_UNAVAILABLE,
                    "baseline service unavailable");
            return;
        }
        if (!StringUtils.hasText(event.getUserId())) {
            applyUnavailableBaselineEvidence(
                    context,
                    BaselineEvidenceStatus.MISSING_USER_ID,
                    "missing user identifier for baseline lookup");
            return;
        }
        event.addMetadata("baselineSeedApplied", false);
        event.addMetadata("baselineSeedWeight", 0.0d);
        event.addMetadata("baselineSeedWeightState", "UNAVAILABLE");
        event.addMetadata("personalBaselineEstablished", false);
        event.addMetadata("organizationBaselineEstablished", false);
        try {
            BaselineVector personalBaseline = baselineLearningService.getPersonalBaseline(event.getUserId());
            if (personalBaseline != null) {
                context.setBaselineIpRanges(personalBaseline.getNormalIpRanges());
                context.setBaselineOperatingSystems(personalBaseline.getNormalOperatingSystems());
                context.setBaselineUserAgents(personalBaseline.getNormalUserAgents());
                context.setBaselineFrequentPaths(personalBaseline.getFrequentPaths());
                context.setBaselineAccessHours(personalBaseline.getNormalAccessHours());
                context.setBaselineAccessDays(personalBaseline.getNormalAccessDays());
                context.setBaselineBrowsers(personalBaseline.getNormalBrowsers());
                context.setBaselineIpBands(personalBaseline.getNormalIpBands());
                context.setBaselineAuthenticationTypes(personalBaseline.getNormalAuthenticationTypes());
                context.setBaselineActionFamilies(personalBaseline.getFrequentActionFamilies());
                context.setBaselineResourceFamilies(personalBaseline.getFrequentResourceFamilies());
                context.setBaselineUpdateCount(personalBaseline.getUpdateCount());
                context.setBaselineAvgTrustScore(personalBaseline.getAvgTrustScore());
                if (personalBaseline.getNormalUserAgents() != null && personalBaseline.getNormalUserAgents().length > 0) {
                    context.setPreviousUserAgentBrowser(personalBaseline.getNormalUserAgents()[0]);
                }
            }
            BaselineLearningService.BaselineMaturitySnapshot maturity =
                    baselineLearningService.describeBaselineMaturity(event.getUserId(), resolveOrganizationId(event));
            if (maturity == null) {
                applyUnavailableBaselineEvidence(
                        context,
                        BaselineEvidenceStatus.ANALYSIS_UNAVAILABLE,
                        "baseline analysis unavailable");
                return;
            }
            context.setPersonalBaselineEvidence(
                    baselineLearningService.buildBaselineEvidenceSnapshot(event.getUserId(), event));
            context.setSupportingBaselineEvidence(
                    baselineLearningService.buildSupportingBaselineEvidenceSnapshot(
                            event.getUserId(),
                            resolveOrganizationId(event)));
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
            CohortSeedRuntimeWeightDecision seedDecision = baselineSeedService.resolvePromptSeed(
                    maturity.personalBaselineEstablished(),
                    maturity.organizationBaselineEstablished());
            if (seedDecision == null || !seedDecision.seedAllowed()) {
                return;
            }
            BaselineSeedSnapshot baselineSeed = seedDecision.seedSnapshot();
            if (baselineSeed == null || !baselineSeed.featureEnabled() || !baselineSeed.seedAvailable()) {
                return;
            }
            context.setCohortBaselineSeed(baselineSeed);
            context.setCohortSeedApplied(true);
            context.setCohortSeedWeight(seedDecision.runtimeWeight());
            context.setCohortSeedWeightState(seedDecision.weightState().name());
            context.setCohortSeedPolicyFacts(seedDecision.policyFacts());
            event.addMetadata("baselineSeedApplied", true);
            event.addMetadata("baselineSeedWeight", seedDecision.runtimeWeight());
            event.addMetadata("baselineSeedWeightState", seedDecision.weightState().name());
            if (!seedDecision.policyFacts().isEmpty()) {
                event.addMetadata("baselineSeedPolicyFacts", List.copyOf(seedDecision.policyFacts()));
            }
        } catch (Exception ex) {
            applyUnavailableBaselineEvidence(
                    context,
                    BaselineEvidenceStatus.SERVICE_UNAVAILABLE,
                    firstNonBlankTextValue(ex.getMessage(), "baseline service unavailable"));
            log.error("[{}] Failed to enrich baseline support context for user {}",
                    getLayerName(), event.getUserId(), ex);
        }
    }

    private void applyUnavailableBaselineEvidence(
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis context,
            BaselineEvidenceStatus status,
            String diagnostic) {
        context.setPersonalBaselineEvidence(unavailableBaseline(LearningEvidenceScope.PERSONAL, status, diagnostic));
        context.setSupportingBaselineEvidence(unavailableBaseline(LearningEvidenceScope.SUPPORTING, status, diagnostic));
        context.setPersonalBaselineAvailable(false);
        context.setPersonalBaselineEstablished(false);
        context.setOrganizationBaselineAvailable(false);
        context.setOrganizationBaselineEstablished(false);
    }

    private BaselineEvidenceSnapshot unavailableBaseline(
            LearningEvidenceScope scope,
            BaselineEvidenceStatus status,
            String diagnostic) {
        return new BaselineEvidenceSnapshot(
                scope,
                false,
                false,
                null,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "",
                status,
                diagnostic);
    }

    protected void hydrateBehaviorAnalysisRuntimeFacts(
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis context,
            SecurityEvent event) {
        if (context == null || event == null) {
            return;
        }

        if (!StringUtils.hasText(context.getCurrentUserAgentOS()) && StringUtils.hasText(event.getUserAgent())) {
            context.setCurrentUserAgentOS(SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent()));
        }
        if (!StringUtils.hasText(context.getCurrentUserAgentBrowser()) && StringUtils.hasText(event.getUserAgent())) {
            context.setCurrentUserAgentBrowser(SecurityEventEnricher.extractBrowserSignature(event.getUserAgent()));
        }

        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return;
        }

        if (context.getIsNewSession() == null) {
            context.setIsNewSession(resolveBooleanMetadata(metadata, "isNewSession", "newSession"));
        }
        if (context.getIsNewDevice() == null) {
            context.setIsNewDevice(resolveBooleanMetadata(metadata, "isNewDevice", "newDevice"));
        }
        if (!StringUtils.hasText(context.getPreviousPath())) {
            context.setPreviousPath(firstTextMetadata(metadata, "previousPath"));
        }
        if (context.getLastRequestIntervalMs() == null) {
            context.setLastRequestIntervalMs(resolveLongMetadata(metadata, "lastRequestIntervalMs"));
        }
        if (context.getContextBindingHashMismatch() == null) {
            context.setContextBindingHashMismatch(resolveBooleanMetadata(metadata, "contextBindingHashMismatch"));
        }
        if (!StringUtils.hasText(context.getPreviousUserAgentOS())) {
            context.setPreviousUserAgentOS(firstTextMetadata(metadata, "previousUserAgentOS"));
        }
        if (!StringUtils.hasText(context.getPreviousUserAgentBrowser())) {
            context.setPreviousUserAgentBrowser(firstTextMetadata(metadata, "previousUserAgentBrowser"));
        }
    }

    private Boolean resolveBooleanMetadata(Map<String, Object> metadata, String... keys) {
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value instanceof Boolean bool) {
                return bool;
            }
            if (value instanceof String text && StringUtils.hasText(text)) {
                if ("true".equalsIgnoreCase(text)) {
                    return true;
                }
                if ("false".equalsIgnoreCase(text)) {
                    return false;
                }
            }
        }
        return null;
    }

    private Long resolveLongMetadata(Map<String, Object> metadata, String... keys) {
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value instanceof Number number) {
                return number.longValue();
            }
            if (value instanceof String text && text.matches("-?\\d+")) {
                return Long.parseLong(text);
            }
        }
        return null;
    }

    private String firstTextMetadata(Map<String, Object> metadata, String... keys) {
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value instanceof String text && StringUtils.hasText(text)) {
                return text;
            }
        }
        return null;
    }
    protected List<Document> searchRelatedContextBase(SecurityEvent event,
                                                       int topK,
                                                       double similarityThreshold) {
        int requestedTopK = Math.max(topK, 1);
        String retrievalPurpose = getContextRetrievalPurpose();
        if (unifiedVectorService == null) {
            capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                    "VECTOR_SERVICE_UNAVAILABLE", null);
            markRagRetrievalUnavailable(event, requestedTopK, null);
            return Collections.emptyList();
        }
        try {
            String targetResource = eventEnricher.getTargetResource(event).orElse(null);
            String query = buildRelatedContextQuery(event, targetResource);
            if (query.isEmpty()) {
                capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                        "VECTOR_QUERY_EMPTY", null);
                markRagRetrievalNotExecuted(event, requestedTopK, "VECTOR_QUERY_EMPTY");
                return Collections.emptyList();
            }

            String userId = event.getUserId();
            if (userId == null || userId.isEmpty() || "unknown".equals(userId)) {
                log.error("[{}] userId missing - skipping RAG search for account isolation",
                    getLayerName());
                capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                        "USER_ID_MISSING", null);
                markRagRetrievalNotExecuted(event, requestedTopK, "USER_ID_MISSING");
                return Collections.emptyList();
            }

            List<Document> personalDocuments = searchBehaviorDocuments(
                    query,
                    requestedTopK,
                    similarityThreshold,
                    buildBehaviorFilterForUser(userId, retrievalPurpose));

            List<Document> mergedDocuments = new ArrayList<>(personalDocuments);
            boolean personalBaselineEstablished = baselineLearningService != null
                    && baselineLearningService.describeBaselineMaturity(userId, resolveOrganizationId(event))
                    .personalBaselineEstablished();
            boolean needSupportingEvidence = personalDocuments.size() < 3 || !personalBaselineEstablished;
            if (needSupportingEvidence) {
                String organizationId = resolveOrganizationId(event);
                if (StringUtils.hasText(organizationId)) {
                    int supportingTopK = Math.max(1, Math.min(requestedTopK, 2));
                    List<Document> supportingDocuments = searchSupportingBehaviorDocuments(
                            query,
                            supportingTopK,
                            similarityThreshold,
                            organizationId,
                            retrievalPurpose,
                            userId);
                    supportingDocuments.stream()
                            .filter(document -> !userId.equalsIgnoreCase(documentUserId(document)))
                            .forEach(mergedDocuments::add);
                }
            }

            if (mergedDocuments.isEmpty()) {
                String broadQuery = buildBroadRelatedContextQuery(event, targetResource);
                if (StringUtils.hasText(broadQuery) && !broadQuery.equals(query)) {
                    double broadThreshold = Math.min(similarityThreshold, 0.35d);
                    List<Document> broadDocuments = searchBehaviorDocuments(
                            broadQuery,
                            requestedTopK,
                            broadThreshold,
                            buildBehaviorFilterForUser(userId, retrievalPurpose));
                    mergedDocuments.addAll(broadDocuments);
                }
            }

            if (mergedDocuments.isEmpty()) {
                String userBaselineQuery = buildUserBaselineContextQuery(event);
                if (StringUtils.hasText(userBaselineQuery)
                        && !userBaselineQuery.equals(query)
                        && !userBaselineQuery.equals(buildBroadRelatedContextQuery(event, targetResource))) {
                    List<Document> userBaselineDocuments = searchBehaviorDocuments(
                            userBaselineQuery,
                            requestedTopK,
                            0.0d,
                            buildBehaviorFilterForUser(userId, retrievalPurpose));
                    mergedDocuments.addAll(userBaselineDocuments);
                }
            }

            List<Document> documents = dedupeDocuments(mergedDocuments, requestedTopK);
            AuthorizedPromptContext limitedAuthorizedPromptContext;
            if (documents == null || documents.isEmpty()) {
                limitedAuthorizedPromptContext = limitAuthorizedPromptContext(null, requestedTopK);
            } else {
                AuthorizedPromptContext authorizedPromptContext = promptContextAuthorizationService
                        .authorize(event, retrievalPurpose, documents);

                limitedAuthorizedPromptContext =
                        limitAuthorizedPromptContext(authorizedPromptContext, requestedTopK);
            }
            capturePromptContextAudit(event, retrievalPurpose, limitedAuthorizedPromptContext);
            annotateRagSearchResult(event, requestedTopK, documents, limitedAuthorizedPromptContext);
            return limitedAuthorizedPromptContext.documents();

        } catch (Exception e) {
            log.error("[{}] Vector store context search failed", getLayerName(), e);
            markRagRetrievalUnavailable(event, requestedTopK, e);
            capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                    "VECTOR_STORE_SEARCH_FAILED", e);
            return Collections.emptyList();
        }
    }

    private void markRagRetrievalUnavailable(SecurityEvent event, int requestedTopK, Exception exception) {
        if (event == null) {
            return;
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null) {
            metadata = new LinkedHashMap<>();
            event.setMetadata(metadata);
        }
        metadata.put("ragUnavailable", true);
        metadata.put("ragTimedOut", false);
        metadata.put("ragSearchExecuted", false);
        metadata.put("ragRetrievalState", "UNAVAILABLE");
        metadata.put("ragAbsenceReason", "UNAVAILABLE");
        metadata.put("ragProjectionState", "UNAVAILABLE_DECLARED");
        metadata.put("ragProjectedToFinalPrompt", false);
        metadata.put("ragStatusProjectedToFinalPrompt", true);
        metadata.put("relatedDocumentCount", 0);
        metadata.put("relatedDocumentsCount", 0);
        metadata.put("ragCandidateDocumentCount", 0);
        metadata.put("ragAuthorizedDocumentCount", 0);
        metadata.put("ragDeniedDocumentCount", 0);
        metadata.put("ragPermissionFiltered", false);
        metadata.put("ragFailureType", exception != null ? exception.getClass().getName() : "unknown");
        metadata.put("ragFailureMessage",
                exception != null && StringUtils.hasText(exception.getMessage())
                        ? exception.getMessage()
                        : "RAG retrieval unavailable");
        metadata.put("ragRequestedTopK", Math.max(0, requestedTopK));
    }

    private void markRagRetrievalNotExecuted(SecurityEvent event, int requestedTopK, String absenceReason) {
        Map<String, Object> metadata = writableMetadata(event);
        if (metadata == null) {
            return;
        }
        metadata.put("ragSearchExecuted", false);
        metadata.put("ragUnavailable", false);
        metadata.put("ragTimedOut", false);
        metadata.put("ragRetrievalState", "NOT_REQUESTED");
        metadata.put("ragAbsenceReason", StringUtils.hasText(absenceReason) ? absenceReason : "NOT_REQUESTED");
        metadata.put("ragProjectionState", "NOT_REQUESTED_DECLARED");
        metadata.put("ragProjectedToFinalPrompt", false);
        metadata.put("ragStatusProjectedToFinalPrompt", true);
        metadata.put("relatedDocumentCount", 0);
        metadata.put("relatedDocumentsCount", 0);
        metadata.put("ragCandidateDocumentCount", 0);
        metadata.put("ragAuthorizedDocumentCount", 0);
        metadata.put("ragDeniedDocumentCount", 0);
        metadata.put("ragPermissionFiltered", false);
        metadata.put("ragRequestedTopK", Math.max(0, requestedTopK));
    }

    private void annotateRagSearchResult(
            SecurityEvent event,
            int requestedTopK,
            List<Document> candidateDocuments,
            AuthorizedPromptContext authorizedPromptContext) {
        Map<String, Object> metadata = writableMetadata(event);
        if (metadata == null) {
            return;
        }
        int candidateCount = candidateDocuments != null ? candidateDocuments.size() : 0;
        int authorizedCount = authorizedPromptContext != null ? authorizedPromptContext.allowedDocumentCount() : 0;
        int deniedCount = authorizedPromptContext != null ? authorizedPromptContext.deniedDocumentCount() : 0;
        int projectedCount = authorizedPromptContext != null && authorizedPromptContext.documents() != null
                ? authorizedPromptContext.documents().size()
                : 0;
        boolean permissionFiltered = candidateCount > 0 && projectedCount == 0 && deniedCount > 0;
        String retrievalState = projectedCount > 0
                ? "AVAILABLE"
                : (permissionFiltered ? "PERMISSION_FILTERED" : "ZERO_RESULTS");
        String absenceReason = projectedCount > 0
                ? null
                : (permissionFiltered ? "PERMISSION_FILTERED" : "ZERO_RESULTS");
        metadata.put("ragSearchExecuted", true);
        metadata.put("ragUnavailable", false);
        metadata.put("ragTimedOut", false);
        metadata.put("ragRetrievalState", retrievalState);
        if (absenceReason != null) {
            metadata.put("ragAbsenceReason", absenceReason);
        } else {
            metadata.remove("ragAbsenceReason");
        }
        metadata.put("ragProjectionState", projectedCount > 0 ? "PROJECTED" : "ZERO_RESULTS_DECLARED");
        metadata.put("ragProjectedToFinalPrompt", projectedCount > 0);
        metadata.put("ragStatusProjectedToFinalPrompt", true);
        metadata.put("relatedDocumentCount", projectedCount);
        metadata.put("relatedDocumentsCount", projectedCount);
        metadata.put("ragCandidateDocumentCount", candidateCount);
        metadata.put("ragAuthorizedDocumentCount", authorizedCount);
        metadata.put("ragDeniedDocumentCount", deniedCount);
        metadata.put("ragPermissionFiltered", permissionFiltered);
        metadata.put("ragRequestedTopK", Math.max(0, requestedTopK));
        metadata.remove("ragFailureType");
        metadata.remove("ragFailureMessage");
    }

    private Map<String, Object> writableMetadata(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null) {
            metadata = new LinkedHashMap<>();
            event.setMetadata(metadata);
        }
        return metadata;
    }

    private String buildRelatedContextQuery(SecurityEvent event, String targetResource) {
        StringBuilder query = new StringBuilder();
        appendQueryPart(query, "user", event != null ? event.getUserId() : null);
        appendQueryPart(query, "tenant", event != null && event.getMetadata() != null
                ? firstNonBlankTextValue(textValue(event.getMetadata().get("tenantId")), textValue(event.getMetadata().get("tenant_id")))
                : null);
        appendQueryPart(query, "path", targetResource);
        appendQueryPart(query, "resource", event != null && event.getMetadata() != null
                ? firstNonBlankTextValue(textValue(event.getMetadata().get("resourceId")), textValue(event.getMetadata().get("ResourceId")))
                : null);
        appendQueryPart(query, "action", SecuritySemanticNormalizer.normalizeActionFamily(
                event != null && event.getMetadata() != null ? event.getMetadata().get("httpMethod") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("method") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("actionFamily") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("ActionFamily") : null));
        appendQueryPart(query, "resourceFamily", SecuritySemanticNormalizer.normalizeResourceFamily(
                event != null && event.getMetadata() != null ? event.getMetadata().get("resourceFamily") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("Sensitivity") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("sensitivity") : null));
        appendQueryPart(query, "auth", SecuritySemanticNormalizer.normalizeAuthenticationType(
                event != null && event.getMetadata() != null ? event.getMetadata().get("authenticationType") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("authType") : null));
        appendQueryPart(query, "network", event != null
                ? SecuritySemanticNormalizer.normalizeNetwork(event.getSourceIp(), event.getMetadata() != null
                ? textValue(event.getMetadata().get("ipBand"))
                : null)
                : null);
        appendQueryPart(query, "browser", event != null && StringUtils.hasText(event.getUserAgent())
                ? SecurityEventEnricher.extractBrowserSignature(event.getUserAgent())
                : null);
        appendQueryPart(query, "os", event != null && StringUtils.hasText(event.getUserAgent())
                ? SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent())
                : null);
        return query.toString().trim();
    }

    private String buildBroadRelatedContextQuery(SecurityEvent event, String targetResource) {
        StringBuilder query = new StringBuilder();
        appendQueryPart(query, "user", event != null ? event.getUserId() : null);
        appendQueryPart(query, "action", SecuritySemanticNormalizer.normalizeActionFamily(
                event != null && event.getMetadata() != null ? event.getMetadata().get("httpMethod") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("method") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("actionFamily") : null));
        appendQueryPart(query, "pathFamily", SecuritySemanticNormalizer.normalizePathFamily(targetResource));
        appendQueryPart(query, "browser", event != null && StringUtils.hasText(event.getUserAgent())
                ? SecurityEventEnricher.extractBrowserSignature(event.getUserAgent())
                : null);
        return query.toString().trim();
    }

    private String buildUserBaselineContextQuery(SecurityEvent event) {
        StringBuilder query = new StringBuilder();
        appendQueryPart(query, "user", event != null ? event.getUserId() : null);
        appendQueryPart(query, "purpose", getContextRetrievalPurpose());
        appendQueryPart(query, "action", SecuritySemanticNormalizer.normalizeActionFamily(
                event != null && event.getMetadata() != null ? event.getMetadata().get("httpMethod") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("method") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("actionFamily") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("ActionFamily") : null));
        appendQueryPart(query, "resourceFamily", SecuritySemanticNormalizer.normalizeResourceFamily(
                event != null && event.getMetadata() != null ? event.getMetadata().get("resourceFamily") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("resourceType") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("resourceCategory") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("Sensitivity") : null,
                event != null && event.getMetadata() != null ? event.getMetadata().get("sensitivity") : null));
        return query.toString().trim();
    }

    private void appendQueryPart(StringBuilder query, String label, String value) {
        if (query == null || !StringUtils.hasText(value)) {
            return;
        }
        if (!query.isEmpty()) {
            query.append(", ");
        }
        query.append(label).append(": ").append(value.trim());
    }

    private List<Document> searchBehaviorDocuments(
            String query,
            int topK,
            double similarityThreshold,
            Filter.Expression filterExpression) {
        SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(Math.max(1, topK))
                .similarityThreshold(similarityThreshold)
                .filterExpression(filterExpression)
                .build();
        List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);
        return documents == null ? List.of() : documents;
    }

    private List<Document> searchSupportingBehaviorDocuments(
            String query,
            int topK,
            double similarityThreshold,
            String organizationId,
            String retrievalPurpose,
            String currentUserId) {
        List<Document> byOrganizationMetadata = searchBehaviorDocuments(
                query,
                topK,
                similarityThreshold,
                buildBehaviorFilterForOrganization(organizationId, retrievalPurpose));
        if (!byOrganizationMetadata.isEmpty()) {
            return byOrganizationMetadata.stream()
                    .filter(document -> belongsToOrganization(document, organizationId))
                    .filter(document -> !currentUserId.equalsIgnoreCase(documentUserId(document)))
                    .toList();
        }

        int fallbackTopK = Math.max(topK * 4, 8);
        return searchBehaviorDocuments(
                query,
                fallbackTopK,
                similarityThreshold,
                buildBehaviorFilterForSupportingFallback(retrievalPurpose)).stream()
                .filter(document -> belongsToOrganization(document, organizationId))
                .filter(document -> !currentUserId.equalsIgnoreCase(documentUserId(document)))
                .limit(topK)
                .toList();
    }

    private Filter.Expression buildBehaviorFilterForUser(String userId, String retrievalPurpose) {
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        List<FilterExpressionBuilder.Op> predicates = new ArrayList<>();
        predicates.add(filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()));
        predicates.add(filterBuilder.eq(VectorDocumentMetadata.USER_ID, userId));
        if (StringUtils.hasText(retrievalPurpose)) {
            predicates.add(filterBuilder.eq(VectorDocumentMetadata.RETRIEVAL_PURPOSE, retrievalPurpose));
        }
        return combinePredicates(filterBuilder, predicates);
    }

    private Filter.Expression buildBehaviorFilterForOrganization(String organizationId, String retrievalPurpose) {
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        List<FilterExpressionBuilder.Op> predicates = new ArrayList<>();
        predicates.add(filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()));
        predicates.add(filterBuilder.eq(VectorDocumentMetadata.ORGANIZATION_ID, organizationId));
        if (StringUtils.hasText(retrievalPurpose)) {
            predicates.add(filterBuilder.eq(VectorDocumentMetadata.RETRIEVAL_PURPOSE, retrievalPurpose));
        }
        return combinePredicates(filterBuilder, predicates);
    }

    private Filter.Expression buildBehaviorFilterForSupportingFallback(String retrievalPurpose) {
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        List<FilterExpressionBuilder.Op> predicates = new ArrayList<>();
        predicates.add(filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()));
        if (StringUtils.hasText(retrievalPurpose)) {
            predicates.add(filterBuilder.eq(VectorDocumentMetadata.RETRIEVAL_PURPOSE, retrievalPurpose));
        }
        return combinePredicates(filterBuilder, predicates);
    }

    private Filter.Expression combinePredicates(
            FilterExpressionBuilder filterBuilder,
            List<FilterExpressionBuilder.Op> predicates) {
        FilterExpressionBuilder.Op combinedPredicate = predicates.getFirst();
        for (int index = 1; index < predicates.size(); index++) {
            combinedPredicate = filterBuilder.and(combinedPredicate, predicates.get(index));
        }
        return combinedPredicate.build();
    }

    private List<Document> dedupeDocuments(List<Document> documents, int maxDocuments) {
        if (documents == null || documents.isEmpty()) {
            return List.of();
        }
        LinkedHashMap<String, Document> deduped = new LinkedHashMap<>();
        for (Document document : documents) {
            if (document == null) {
                continue;
            }
            String key = firstNonBlankTextValue(
                    textValue(document.getMetadata() != null ? document.getMetadata().get(VectorDocumentMetadata.ID) : null),
                    textValue(document.getMetadata() != null ? document.getMetadata().get(VectorDocumentMetadata.ARTIFACT_ID) : null),
                    textValue(document.getMetadata() != null ? document.getMetadata().get(VectorDocumentMetadata.EVENT_ID) : null),
                    textValue(document.getMetadata() != null ? document.getMetadata().get("requestPath") : null),
                    document.getText());
            if (!StringUtils.hasText(key) || !deduped.containsKey(key)) {
                deduped.put(key, document);
            }
            if (deduped.size() >= maxDocuments) {
                break;
            }
        }
        return List.copyOf(deduped.values());
    }

    private String documentUserId(Document document) {
        if (document == null || document.getMetadata() == null) {
            return null;
        }
        return textValue(document.getMetadata().get(VectorDocumentMetadata.USER_ID));
    }

    private String documentOrganizationId(Document document) {
        if (document == null || document.getMetadata() == null) {
            return null;
        }
        String metadataOrganizationId = firstNonBlankTextValue(
                textValue(document.getMetadata().get(VectorDocumentMetadata.ORGANIZATION_ID)),
                textValue(document.getMetadata().get("organizationId")),
                textValue(document.getMetadata().get("tenantId")),
                textValue(document.getMetadata().get("orgId")));
        return metadataOrganizationId;
    }

    private boolean belongsToOrganization(Document document, String organizationId) {
        if (!StringUtils.hasText(organizationId)) {
            return false;
        }
        return organizationId.equalsIgnoreCase(documentOrganizationId(document));
    }

    private String resolveOrganizationId(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        if (event.getMetadata() != null) {
            String metadataOrganizationId = firstNonBlankTextValue(
                    textValue(event.getMetadata().get(VectorDocumentMetadata.ORGANIZATION_ID)),
                    textValue(event.getMetadata().get("organizationId")),
                    textValue(event.getMetadata().get("tenantId")),
                    textValue(event.getMetadata().get("orgId")));
            if (StringUtils.hasText(metadataOrganizationId)) {
                return metadataOrganizationId;
            }
        }
        return null;
    }

    private String firstNonBlankTextValue(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value;
            }
        }
        return null;
    }

    private String textValue(Object value) {
        if (value == null) {
            return null;
        }
        String rendered = String.valueOf(value).trim();
        return rendered.isEmpty() ? null : rendered;
    }

    private void capturePromptContextAudit(
            SecurityEvent event,
            String retrievalPurpose,
            AuthorizedPromptContext authorizedPromptContext) {
        if (promptContextAuditForwardingService == null || event == null || authorizedPromptContext == null) {
            return;
        }
        try {
            promptContextAuditForwardingService.capture(event, retrievalPurpose, authorizedPromptContext);
        } catch (Exception captureException) {
            log.error("[{}] Prompt context audit capture failed", getLayerName(), captureException);
        }
    }

    private void capturePromptContextAuditFallback(
            SecurityEvent event,
            String retrievalPurpose,
            int requestedTopK,
            String failureCode,
            Exception exception) {
        AuthorizedPromptContext fallbackPromptContext = new AuthorizedPromptContext(
                List.of(),
                requestedTopK,
                0,
                0,
                retrievalPurpose,
                buildPromptContextAuditFallbackReasons(failureCode, exception));
        capturePromptContextAudit(event, retrievalPurpose, fallbackPromptContext);
    }

    private List<String> buildPromptContextAuditFallbackReasons(String failureCode, Exception exception) {
        List<String> fallbackReasons = new ArrayList<>();
        if (StringUtils.hasText(failureCode)) {
            fallbackReasons.add(failureCode.trim());
        }
        if (exception != null) {
            fallbackReasons.add(exception.getClass().getSimpleName());
            if (StringUtils.hasText(exception.getMessage())) {
                fallbackReasons.add(exception.getMessage().trim());
            }
        }
        return fallbackReasons.isEmpty() ? List.of("PROMPT_CONTEXT_AUDIT_FALLBACK") : List.copyOf(fallbackReasons);
    }

    private AuthorizedPromptContext limitAuthorizedPromptContext(
            AuthorizedPromptContext authorizedPromptContext,
            int requestedTopK) {
        if (authorizedPromptContext == null || authorizedPromptContext.documents().isEmpty()) {
            return new AuthorizedPromptContext(
                    List.of(),
                    0,
                    0,
                    0,
                    getContextRetrievalPurpose(),
                    List.of());
        }

        if (authorizedPromptContext.documents().size() <= requestedTopK) {
            return authorizedPromptContext;
        }

        List<Document> limitedDocuments = authorizedPromptContext.documents()
                .subList(0, requestedTopK);
        return new AuthorizedPromptContext(
                limitedDocuments,
                authorizedPromptContext.requestedDocumentCount(),
                limitedDocuments.size(),
                Math.max(0,
                        authorizedPromptContext.deniedDocumentCount()
                                + (authorizedPromptContext.allowedDocumentCount() - limitedDocuments.size())),
                authorizedPromptContext.retrievalPurpose(),
                authorizedPromptContext.deniedReasons(),
                authorizedPromptContext.retrievalPolicy(),
                authorizedPromptContext.provenanceRecords(),
                authorizedPromptContext.contextItems());
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
        public void setRecentActions(List<String> recentActions) {
            this.recentActions = recentActions != null
                    ? new ArrayList<>(recentActions)
                    : new ArrayList<>();
        }

        public int getAccessFrequency() { return accessFrequency; }
        public void setAccessFrequency(int accessFrequency) { this.accessFrequency = accessFrequency; }
    }


    protected static class BaseBehaviorAnalysis {
        protected List<String> similarEvents = new ArrayList<>();
        protected boolean baselineEstablished;

        public List<String> getSimilarEvents() { return similarEvents; }
        public void setSimilarEvents(List<String> events) { this.similarEvents = events; }

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
        PromptBudgetProfile promptBudgetProfile = resolvePromptBudgetProfile(event);
        request.withParameter("responseType", SecurityDecisionResponse.class);
        request.withParameter("promptBudgetProfile", promptBudgetProfile.profileKey());
        StructuredOutputCapability structuredOutputCapability = resolveStructuredOutputCapability(event);
        request.withParameter("structuredOutputMode", resolveStructuredOutputMode(event, structuredOutputCapability).name());
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());
        request.withParameter("structuredOutputValidationMaxAttempts", 1);
        request.withParameter("strictResponsePostprocessing", true);
        request.withParameter("pipelineFailurePolicy", PipelineFailurePolicy.PROPAGATE_ERROR.name());
        request.withParameter(
                "nativeStructuredOutputEnabled",
                tieredStrategyProperties.getPromptRuntime().isNativeStructuredOutputEnabledForProfile(promptBudgetProfile.profileKey()));
        request.withParameter("structuredOutputProviderFamily", structuredOutputCapability.providerFamily());
        request.withParameter("structuredOutputNativeSupported", structuredOutputCapability.nativeStructuredSupported());
        request.withParameter("structuredOutputValidationAdvisorSupported", structuredOutputCapability.validationAdvisorSupported());
        request.withParameter("structuredOutputCapabilitySource", structuredOutputCapability.resolutionSource());
        applyRuntimeSelectionOptions(request, event);
        return request;
    }

    protected StructuredOutputMode resolveStructuredOutputMode(SecurityEvent event, StructuredOutputCapability capability) {
        if (event != null && event.getMetadata() != null) {
            StructuredOutputMode explicit = StructuredOutputMode.fromValue(
                    event.getMetadata().get("structuredOutputMode"),
                    null);
            if (explicit != null) {
                return explicit;
            }
            Object nativeStructuredEnabled = event.getMetadata().get("nativeStructuredOutputEnabled");
            if (nativeStructuredEnabled instanceof Boolean enabled && !enabled) {
                return StructuredOutputMode.VALIDATED_CONVERTER;
            }
        }
        return capability.resolvePreferredMode();
    }

    protected StructuredOutputCapability resolveStructuredOutputCapability(SecurityEvent event) {
        String modelHint = null;
        String providerHint = null;
        if (event != null && event.getMetadata() != null) {
            modelHint = firstNonBlank(
                    event.getMetadata().get("requestedModelId"),
                    event.getMetadata().get("preferredModel"),
                    event.getMetadata().get("runtimeModelId"),
                    event.getMetadata().get("officialVerificationPinnedModelId"));
            providerHint = firstNonBlank(
                    event.getMetadata().get("selectedModelProvider"),
                    event.getMetadata().get("providerResponseModel"));
        }
        return structuredOutputCapabilityRegistry.resolve(modelHint, providerHint, true);
    }

    private String firstNonBlank(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = String.valueOf(value).trim();
            if (!text.isEmpty()) {
                return text;
            }
        }
        return null;
    }

    protected void applyRuntimeSelectionOptions(SecurityDecisionRequest request, SecurityEvent event) {
        if (request == null || event == null || event.getMetadata() == null) {
            return;
        }
        Map<String, Object> metadata = event.getMetadata();
        copyRuntimeSelectionOption(metadata, request, "requestedModelId");
        copyRuntimeSelectionOption(metadata, request, "preferredModel");
        copyRuntimeSelectionOption(metadata, request, "runtimeModelId");
        copyRuntimeSelectionOption(metadata, request, "temperature");
        copyRuntimeSelectionOption(metadata, request, "topP");
        copyRuntimeSelectionOption(metadata, request, "seed");
        copyRuntimeSelectionOption(metadata, request, "maxTokens");
        copyRuntimeSelectionOption(metadata, request, "disableRetries");
        copyRuntimeSelectionOption(metadata, request, "disableOllamaThinking");
        copyRuntimeSelectionOption(metadata, request, "decisionBoundaryMode");
        copyRuntimeSelectionOption(metadata, request, "officialVerificationDecisionBoundaryMode");
        copyRuntimeSelectionOption(metadata, request, "officialVerificationPinnedModelId");
        copyRuntimeSelectionOption(metadata, request, "officialVerificationTemperature");
        copyRuntimeSelectionOption(metadata, request, "officialVerificationTopP");
        copyRuntimeSelectionOption(metadata, request, "officialVerificationSeed");
        copyRuntimeSelectionOption(metadata, request, "officialVerificationMaxTokens");
        copyRuntimeSelectionOption(metadata, request, "officialVerificationDisableRetries");
        copyRuntimeSelectionOption(metadata, request, "officialVerificationDisableOllamaThinking");
        if (request.getParameter("officialVerificationDecisionBoundaryMode", Object.class) == null
                && hasOfficialVerificationRuntimeOption(metadata)) {
            request.withParameter("officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME");
        }
    }

    private void copyRuntimeSelectionOption(
            Map<String, Object> metadata,
            SecurityDecisionRequest request,
            String key) {
        if (metadata == null || request == null || !StringUtils.hasText(key)) {
            return;
        }
        Object value = metadata.get(key);
        if (value != null) {
            request.withParameter(key, value);
        }
    }

    private boolean hasOfficialVerificationRuntimeOption(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return false;
        }
        return metadata.containsKey("officialVerificationDecisionBoundaryMode")
                || metadata.containsKey("officialVerificationPinnedModelId")
                || metadata.containsKey("officialVerificationTemperature")
                || metadata.containsKey("officialVerificationTopP")
                || metadata.containsKey("officialVerificationSeed")
                || metadata.containsKey("officialVerificationMaxTokens")
                || metadata.containsKey("officialVerificationDisableRetries")
                || metadata.containsKey("officialVerificationDisableOllamaThinking");
    }

    protected PromptBudgetProfile resolvePromptBudgetProfile(SecurityEvent event) {
        if (event != null && event.getMetadata() != null) {
            Object explicitProfile = event.getMetadata().get("promptBudgetProfile");
            if (explicitProfile instanceof PromptBudgetProfile budgetProfile) {
                return budgetProfile;
            }
            if (explicitProfile instanceof String profileKey && !profileKey.isBlank()) {
                return PromptBudgetProfile.fromKey(profileKey, resolvePromptBudgetProfile());
            }
        }
        return resolvePromptBudgetProfile();
    }

    protected PromptBudgetProfile resolvePromptBudgetProfile() {
        String layerName = getLayerName();
        if (layerName != null && layerName.toLowerCase(Locale.ROOT).contains("layer2")) {
            String configuredProfile = tieredStrategyProperties != null && tieredStrategyProperties.getLayer2() != null
                    ? tieredStrategyProperties.getLayer2().getDefaultBudgetProfile()
                    : null;
            return PromptBudgetProfile.fromKey(configuredProfile, PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT);
        }
        String configuredProfile = tieredStrategyProperties != null && tieredStrategyProperties.getLayer1() != null
                ? tieredStrategyProperties.getLayer1().getDefaultBudgetProfile()
                : null;
        return PromptBudgetProfile.fromKey(configuredProfile, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
    }

    protected void clearPromptRuntimeTelemetry(SecurityEvent event) {
        if (event == null) {
            return;
        }
        Map<String, Object> metadata = ensureMutableEventMetadata(event);
        for (String key : PromptRuntimeTelemetrySupport.clearableRuntimeTelemetryKeys()) {
            metadata.remove(key);
        }
        metadata.remove("systemPrompt");
        metadata.remove("userPrompt");
        metadata.remove("rawSystemPrompt");
        metadata.remove("rawUserPrompt");
        metadata.remove("promptSourceContextLedger");
        metadata.remove("promptSourceContextSummary");
        metadata.remove("promptRawUserFieldLedger");
        metadata.remove("promptFinalUserFieldLedger");
        metadata.remove("promptUserFieldDiffLedger");
        metadata.remove("promptUserFieldLineageSummary");
        metadata.remove("promptFieldStateLedger");
        metadata.remove("promptFieldStateSummary");
        metadata.remove("promptRuntimeTelemetryLinked");
        metadata.remove("promptRuntimeTelemetryLayer");
    }

    protected void capturePromptRuntimeTelemetry(SecurityEvent event, SecurityDecisionResponse pipelineResponse) {
        if (event == null || pipelineResponse == null) {
            return;
        }
        Map<String, Object> metadata = ensureMutableEventMetadata(event);
        Map<String, Object> responseMetadata = pipelineResponse.getAllMetadata();
        Map<String, Object> telemetry = PromptRuntimeTelemetrySupport.extractRuntimeTelemetry(responseMetadata);
        if (!telemetry.isEmpty()) {
            metadata.putAll(telemetry);
            metadata.put("promptRuntimeTelemetryLinked", true);
            metadata.put("promptRuntimeTelemetryLayer", getLayerName());
        }
        copyPromptTextIfPresent(responseMetadata, metadata, "systemPrompt");
        copyPromptTextIfPresent(responseMetadata, metadata, "userPrompt");
        copyPromptTextIfPresent(responseMetadata, metadata, "rawSystemPrompt");
        copyPromptTextIfPresent(responseMetadata, metadata, "rawUserPrompt");
        if (promptContextAuditForwardingService != null && hasPromptLineage(metadata)) {
            promptContextAuditForwardingService.enrich(event);
        }
    }

    private void copyPromptTextIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
        if (source == null || target == null || !StringUtils.hasText(key)) {
            return;
        }
        Object value = source.get(key);
        if (value instanceof String text && !text.isBlank()) {
            target.put(key, text);
        }
    }

    private boolean hasPromptLineage(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return false;
        }
        return StringUtils.hasText(readMetadataText(metadata, "promptHash"))
                || StringUtils.hasText(readMetadataText(metadata, "systemPromptHash"))
                || StringUtils.hasText(readMetadataText(metadata, "userPromptHash"))
                || StringUtils.hasText(readMetadataText(metadata, "systemPrompt"))
                || StringUtils.hasText(readMetadataText(metadata, "userPrompt"));
    }

    private String readMetadataText(Map<String, Object> metadata, String key) {
        if (metadata == null || !StringUtils.hasText(key)) {
            return null;
        }
        Object value = metadata.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }

    private Map<String, Object> ensureMutableEventMetadata(SecurityEvent event) {
        Map<String, Object> current = event.getMetadata();
        if (current == null) {
            Map<String, Object> fresh = new LinkedHashMap<>();
            event.setMetadata(fresh);
            return fresh;
        }
        if (current instanceof HashMap) {
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
