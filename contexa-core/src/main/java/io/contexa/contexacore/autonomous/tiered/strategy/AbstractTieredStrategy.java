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

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.context.support.PastRecordScope;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.context.support.PastRecordGroup;
import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacommon.domain.TruthValues;
import io.contexa.contexacore.autonomous.context.support.PastRecordRanking;
import java.time.Instant;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;
import io.contexa.contexacore.autonomous.context.support.PastRecordRelevance;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityResponse;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.saas.learning.cohort.CohortSeedRuntimeWeightDecision;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditRecorder;
import io.contexa.contexacore.autonomous.saas.SaasBaselineSeedService;
import io.contexa.contexacore.autonomous.saas.SaasDetectionStrategyPackService;
import io.contexa.contexacore.autonomous.saas.SaasThreatIntelligenceService;
import io.contexa.contexacore.autonomous.saas.SaasThreatKnowledgePackService;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.llm.client.ChatModelProviders;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.StructuredOutputChatOptions;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapability;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineFailurePolicy;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.step.StructuredOutputExecutionException;
import io.contexa.contexacore.std.pipeline.step.StructuredOutputPolicy;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;


@Slf4j
public abstract class AbstractTieredStrategy implements ThreatEvaluationStrategy {

    private static final ExecutorService RAG_EXECUTOR = createRagExecutor();
    private static final String SAME_RESOURCE_RAG_ALLOW_REASONING =
            "Authorization allows access, and authorized RAG is relevant to the same resource.";
    private static final String SAME_RESOURCE_RAG_ESTABLISHED_BASELINE_ALLOW_REASONING =
            "Authorization allows access, the personal baseline is established, "
                    + "and authorized RAG is relevant to the same resource.";
    private static final String ESTABLISHED_BASELINE_ALLOW_REASONING =
            "Authorization allows access, the personal baseline is established, "
                    + "and no concrete risk or verification requirement is present.";
    private static final String LIMITED_BASELINE_ALLOW_REASONING =
            "Authorization allows access with a limited baseline, "
                    + "and no concrete risk or verification requirement is present.";

    private static ExecutorService createRagExecutor() {
        return new ThreadPoolExecutor(
                32, 32, 60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(500),
                r -> {
                    Thread thread = new Thread(r, "contexa-tiered-rag-worker");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
    }

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
    private Supplier<ModelSelectionStrategy> modelSelectionStrategy;
    private MinimumActionRules.Settings minimumActionSettings = MinimumActionRules.Settings.DEFAULTS;
    private String minimumActionMode = "OBSERVE";
    protected final PromptContextAuthorizationService promptContextAuthorizationService;
    protected final PromptContextAuditRecorder promptContextAuditRecorder;
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
            PromptContextAuditRecorder promptContextAuditRecorder,
            TieredStrategyProperties tieredStrategyProperties) {
        this(
                eventEnricher,
                promptTemplate,
                behaviorVectorService,
                unifiedVectorService,
                baselineLearningService,
                promptContextAuthorizationService,
                promptContextAuditRecorder,
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
            PromptContextAuditRecorder promptContextAuditRecorder,
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
        this.promptContextAuditRecorder = promptContextAuditRecorder;
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
                .fieldProvenance(platformFallbackFieldProvenance())
                .build();
    }

    private Map<String, String> platformFallbackFieldProvenance() {
        Map<String, String> provenance = new LinkedHashMap<>();
        for (String field : List.of("riskScore", "confidence", "reasoning", "mitre", "evidenceRefs")) {
            provenance.put(field, "PLATFORM_FALLBACK");
        }
        return Map.copyOf(provenance);
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
        if (!StringUtils.hasText(action)) {
            return ZeroTrustAction.ESCALATE;
        }
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
                analysis.setBaselineEstablished(baselineLearningService.getPersonalBaseline(userId, event) != null);

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
            BaselineLearningService.PromptBaselineEvidence baselineEvidence =
                    baselineLearningService.buildPromptBaselineEvidenceSnapshot(event.getUserId(), event);
            BaselineVector personalBaseline = baselineEvidence.personalBaseline();
            if (personalBaseline != null) {
                context.setBaselineIpRanges(personalBaseline.getNormalIpRanges());
                context.setBaselineOperatingSystems(personalBaseline.getNormalOperatingSystems());
                context.setBaselineUserAgents(personalBaseline.getNormalUserAgents());
                context.setBaselineFrequentPaths(personalBaseline.getFrequentPaths());
                context.setBaselineAccessHours(personalBaseline.getNormalAccessHours());
                context.setBaselineAccessDays(personalBaseline.getNormalAccessDays());
                context.setBaselineBrowsers(personalBaseline.getNormalBrowsers());
                context.setBaselineDevices(personalBaseline.getNormalDevices());
                context.setBaselineIpBands(personalBaseline.getNormalIpBands());
                context.setBaselineAuthenticationTypes(personalBaseline.getNormalAuthenticationTypes());
                context.setBaselineActionFamilies(personalBaseline.getFrequentActionFamilies());
                context.setBaselineResourceFamilies(personalBaseline.getFrequentResourceFamilies());
                context.setBaselineUpdateCount(personalBaseline.getUpdateCount());
                context.setBaselineAvgTrustScore(personalBaseline.getAvgTrustScore());
            }
            BaselineLearningService.BaselineMaturitySnapshot maturity = baselineEvidence.maturity();
            if (maturity == null) {
                applyUnavailableBaselineEvidence(
                        context,
                        BaselineEvidenceStatus.ANALYSIS_UNAVAILABLE,
                        "baseline analysis unavailable");
                return;
            }
            context.setPersonalBaselineEvidence(baselineEvidence.personal());
            context.setSupportingBaselineEvidence(baselineEvidence.supporting());
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
        // A change of device or network within the session, when the event already carries one (W2-14).
        if (!StringUtils.hasText(context.getSessionDeviceChange())) {
            context.setSessionDeviceChange(firstTextMetadata(metadata, "sessionDeviceChange"));
        }
        if (!StringUtils.hasText(context.getSessionNetworkChange())) {
            context.setSessionNetworkChange(firstTextMetadata(metadata, "sessionNetworkChange"));
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
            Boolean parsed = TruthValues.parse(metadata.get(key));
            if (parsed != null) {
                return parsed;
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
        String searchId = beginRagSearch(event);
        if (unifiedVectorService == null) {
            capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                    "VECTOR_SERVICE_UNAVAILABLE", null);
            markRagRetrievalUnavailable(event, requestedTopK, null);
            return Collections.emptyList();
        }
        if (readsPastRecordsExactly(event)) {
            return searchPastRecordsExactly(event, searchId, retrievalPurpose, requestedTopK);
        }
        try {
            String targetResource = eventEnricher.getTargetResource(event).orElse(null);
            String resourceId = firstTextMetadata(event.getMetadata(),
                    "resourceId", "requestedResourceId", "protectableResourceId", "protectedResourceId");
            String resourceScope = StringUtils.hasText(resourceId) ? resourceId : targetResource;
            String query = buildRelatedContextQuery(event, targetResource);
            if (query.isEmpty()) {
                capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                        "VECTOR_QUERY_EMPTY", null);
                markRagRetrievalNotExecuted(event, requestedTopK, "VECTOR_QUERY_EMPTY");
                return Collections.emptyList();
            }

            String userId = event.getUserId();
            List<String> sessionIds = sessionIdsOf(event);
            if (userId == null || userId.isEmpty() || "unknown".equals(userId)) {
                log.error("[{}] userId missing - skipping RAG search for account isolation",
                    getLayerName());
                capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                        "USER_ID_MISSING", null);
                markRagRetrievalNotExecuted(event, requestedTopK, "USER_ID_MISSING");
                return Collections.emptyList();
            }

            if (isLayer1SingleUserRagSearchEnabled()) {
                List<Document> documents = searchBehaviorDocuments(query, requestedTopK, similarityThreshold,
                        buildBehaviorFilterForUser(userId, retrievalPurpose, resourceScope, sessionIds));
                annotateRagSearchPlan(event, "LAYER1_SINGLE_USER_QUERY", 1,
                        List.of("BROAD_QUERY", "BASELINE_QUERY", "SUPPORTING_QUERY"));

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
                annotateRagSearchResult(event, searchId, requestedTopK, documents, limitedAuthorizedPromptContext);
                return limitedAuthorizedPromptContext.documents();
            }
            // 1. Search behavior documents scoped to the current user.
            CompletableFuture<List<Document>> personalFuture = CompletableFuture.supplyAsync(() ->
                    searchBehaviorDocuments(query, requestedTopK, similarityThreshold,
                            buildBehaviorFilterForUser(userId, retrievalPurpose, resourceScope, sessionIds)), RAG_EXECUTOR);

            // 2. Search broader related context when it differs from the personal query.
            String broadQuery = buildBroadRelatedContextQuery(event, targetResource);
            final double broadThreshold = Math.min(similarityThreshold, 0.35d);
            boolean runBroad = StringUtils.hasText(broadQuery) && !broadQuery.equals(query);
            CompletableFuture<List<Document>> broadFuture = runBroad
                    ? CompletableFuture.supplyAsync(() ->
                            searchBehaviorDocuments(broadQuery, requestedTopK, broadThreshold,
                                    buildBehaviorFilterForUser(userId, retrievalPurpose, resourceScope, sessionIds)), RAG_EXECUTOR)
                    : CompletableFuture.completedFuture(Collections.emptyList());

            // 3. Search the user baseline context when it adds another signal.
            String userBaselineQuery = buildUserBaselineContextQuery(event);
            boolean runBaseline = StringUtils.hasText(userBaselineQuery)
                    && !userBaselineQuery.equals(query)
                    && (!runBroad || !userBaselineQuery.equals(broadQuery));
            CompletableFuture<List<Document>> baselineFuture = runBaseline
                    ? CompletableFuture.supplyAsync(() ->
                            searchBehaviorDocuments(userBaselineQuery, requestedTopK, 0.0d,
                                    buildBehaviorFilterForUser(userId, retrievalPurpose, resourceScope, sessionIds)), RAG_EXECUTOR)
                    : CompletableFuture.completedFuture(Collections.emptyList());

            // 4. Search supporting organization documents when the personal baseline is not established.
            boolean personalBaselineEstablished = false;
            if (baselineLearningService != null) {
                var maturity = baselineLearningService.describeBaselineMaturity(userId, resolveOrganizationId(event),
                        event);
                if (maturity != null) {
                    personalBaselineEstablished = maturity.personalBaselineEstablished();
                }
            }
            boolean predictNeedSupporting = !personalBaselineEstablished;
            String organizationId = resolveOrganizationId(event);
            boolean runSupporting = predictNeedSupporting && isLayer1SupportingRagSearchEnabled() && StringUtils.hasText(organizationId);

            CompletableFuture<List<Document>> supportingFuture = runSupporting
                    ? CompletableFuture.supplyAsync(() -> {
                            int supportingTopK = Math.max(1, Math.min(requestedTopK, 2));
                            return searchSupportingBehaviorDocuments(
                                    query,
                                    supportingTopK,
                                    similarityThreshold,
                                    organizationId,
                                    retrievalPurpose,
                                    userId);
                        }, RAG_EXECUTOR)
                    : CompletableFuture.completedFuture(Collections.emptyList());

            // 5. Wait for the parallel RAG searches and merge the results.
            CompletableFuture.allOf(personalFuture, broadFuture, baselineFuture, supportingFuture).join();

            List<Document> personalDocuments = personalFuture.get();
            List<Document> broadDocuments = broadFuture.get();
            List<Document> userBaselineDocuments = baselineFuture.get();
            List<Document> supportingDocuments = supportingFuture.get();

            List<Document> mergedDocuments = new ArrayList<>(personalDocuments);
            if (mergedDocuments.size() < requestedTopK) {
                mergedDocuments.addAll(broadDocuments);
            }
            if (mergedDocuments.size() < requestedTopK) {
                mergedDocuments.addAll(userBaselineDocuments);
            }

            // Add supporting evidence only when personal evidence is sparse or the baseline is immature.
            boolean needSupportingEvidence = personalDocuments.size() < 3 || !personalBaselineEstablished;
            if (needSupportingEvidence) {
                if (!runSupporting && isLayer1SupportingRagSearchEnabled() && StringUtils.hasText(organizationId)) {
                    int supportingTopK = Math.max(1, Math.min(requestedTopK, 2));
                    supportingDocuments = searchSupportingBehaviorDocuments(
                            query,
                            supportingTopK,
                            similarityThreshold,
                            organizationId,
                            retrievalPurpose,
                            userId);
                }
                List<Document> finalSupporting = supportingDocuments;
                finalSupporting.stream()
                        .filter(document -> !userId.equalsIgnoreCase(documentUserId(document)))
                        .forEach(mergedDocuments::add);
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
            annotateRagSearchResult(event, searchId, requestedTopK, documents, limitedAuthorizedPromptContext);
            return limitedAuthorizedPromptContext.documents();

        } catch (Exception e) {
            Throwable cause = e;
            while ((cause instanceof CompletionException
                    || cause instanceof ExecutionException)
                    && cause.getCause() != null) {
                cause = cause.getCause();
            }
            Exception targetException = cause instanceof Exception ? (Exception) cause : new RuntimeException(cause);
            log.error("[{}] Vector store context search failed", getLayerName(), targetException);
            markRagRetrievalUnavailable(event, requestedTopK, targetException);
            capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                    "VECTOR_STORE_SEARCH_FAILED", targetException);
            return Collections.emptyList();
        }
    }

    /** Whether the event runs a v20 bundle, which reads its past records by the exact lookup (W3-18). */
    private boolean readsPastRecordsExactly(SecurityEvent event) {
        return runsV20Bundle(event);
    }

    /** The minimum-action rule settings the host configured and how a weaker decision is handled (W4-4). */
    /**
     * W4-2: the model selection the analysis runs through. A security decision names no model, so its structured
     * output capability is that of the chat model the selection picks; taken when needed, not at creation.
     */
    public void setModelSelectionStrategy(Supplier<ModelSelectionStrategy> modelSelectionStrategy) {
        this.modelSelectionStrategy = modelSelectionStrategy;
    }

    public void setMinimumActionSettings(MinimumActionRules.Settings settings, String mode) {
        this.minimumActionSettings = settings != null ? settings : MinimumActionRules.Settings.DEFAULTS;
        this.minimumActionMode = mode != null ? mode : "OBSERVE";
    }

    /**
     * Records the minimum-action rules the decision facts of the request meet and whether the decision is weaker
     * (W4-4, plan 7). The decision is kept as it is: observe mode only records; correcting it is the response check's
     * (W4-5). The rules read the facts the prompt stated, from the canonical context the prompt was built on.
     */
    protected void applyMinimumActionRules(SecurityDecision decision, SecurityEvent event) {
        if (decision == null) {
            return;
        }
        List<MinimumActionRules.Hit> hits = minimumActionHits(event);
        if (hits.isEmpty()) {
            return;
        }
        String decided = decision.getAction() != null ? decision.getAction().name() : null;
        List<Map<String, Object>> findings = new ArrayList<>();
        for (MinimumActionRules.Hit hit : hits) {
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("rule", hit.rule().name());
            finding.put("code", hit.rule().code());
            finding.put("requiredAction", hit.requiredAction());
            finding.put("dimensions", hit.dimensions().stream().map(Enum::name).toList());
            finding.put("decidedAction", decided);
            finding.put("violated", MinimumActionRules.violatedBy(decided, List.of(hit)));
            findings.add(finding);
        }
        Map<String, Object> metadata = ensureMutableEventMetadata(event);
        metadata.put("minimumActionMode", minimumActionMode);
        metadata.put("minimumActionFindings", List.copyOf(findings));
    }

    /** The minimum action rules the decision facts the prompt stated meet; empty without those facts. */
    protected List<MinimumActionRules.Hit> minimumActionHits(SecurityEvent event) {
        if (event == null || event.getMetadata() == null
                || !(event.getMetadata().get("sealedEvidence.canonicalContext") instanceof CanonicalSecurityContext canonical)
                || canonical.getDecisionFacts() == null) {
            return List.of();
        }
        CanonicalSecurityContext.Resource resource = canonical.getResource();
        return MinimumActionRules.evaluate(canonical.getDecisionFacts(),
                resource != null ? resource.getResourceClass() : null,
                resource != null ? resource.getActionFamily() : null,
                minimumActionSettings);
    }

    /** Whether the event runs a v20 bundle (dictionary blocks, output contract v3). */
    private boolean runsV20Bundle(SecurityEvent event) {
        SecurityDecisionPromptBundles.Bundle bundle = promptBundleOf(event);
        return bundle != null && bundle.layout() == SecurityDecisionPromptBundles.UserPromptLayout.V20_BLOCKS;
    }

    /** The bundle the event runs, fixed on the event for its later prompts; null without a template. */
    protected SecurityDecisionPromptBundles.Bundle promptBundleOf(SecurityEvent event) {
        return promptTemplate != null && event != null ? promptTemplate.promptBundle(event) : null;
    }

    /**
     * The past records of a v20 request (W3-18): the user's own allowed records of the request's action family, read by
     * an exact metadata lookup with no embedding call. The records are counted on the request's target, on other
     * targets and through its entry point; those shown are the ones on its target first, then the latest, then by the
     * stored ID. A similarity decides nothing here.
     */
    private List<Document> searchPastRecordsExactly(SecurityEvent event, String searchId, String retrievalPurpose,
                                                    int requestedTopK) {
        String userId = event.getUserId();
        if (userId == null || userId.isEmpty() || "unknown".equals(userId)) {
            log.error("[{}] userId missing - skipping the past record lookup for account isolation", getLayerName());
            capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK, "USER_ID_MISSING", null);
            markRagRetrievalNotExecuted(event, requestedTopK, "USER_ID_MISSING");
            return Collections.emptyList();
        }
        PastRecordQuery query = unifiedVectorService.pastRecordQuery();
        if (query == null || !query.available()) {
            capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                    "EXACT_PAST_RECORD_LOOKUP_UNAVAILABLE", null);
            markRagRetrievalUnavailable(event, requestedTopK, null);
            return Collections.emptyList();
        }
        PastRecordRelevance.Subject request = PastRecordRelevance.Subject.ofRequest(event.getMetadata(),
                eventEnricher.getTargetResource(event).orElse(null));
        if (request.actionFamily() == null) {
            capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK, "ACTION_FAMILY_UNKNOWN", null);
            markRagRetrievalNotExecuted(event, requestedTopK, "ACTION_FAMILY_UNKNOWN");
            return Collections.emptyList();
        }
        try {
            PastRecordScope scope = new PastRecordScope(userId, retrievalPurpose, request.actionFamily().name(),
                    sessionIdsOf(event));
            List<PastRecordGroup> groups = query.groups(scope);
            List<String> sameTargetPaths = groups.stream()
                    .filter(group -> group.path() != null && PastRecordRelevance.YES.equals(PastRecordRelevance.sameTarget(
                            request, PastRecordRelevance.Subject.ofRecord(groupMetadata(group), null))))
                    .map(PastRecordGroup::path)
                    .distinct()
                    .toList();
            List<Document> documents = query.records(scope, sameTargetPaths, requestedTopK);
            annotateRagSearchPlan(event, "EXACT_PAST_RECORD_LOOKUP", 1,
                    List.of("PERSONAL_QUERY", "BROAD_QUERY", "BASELINE_QUERY", "SUPPORTING_QUERY"));
            AuthorizedPromptContext limitedAuthorizedPromptContext = documents.isEmpty()
                    ? limitAuthorizedPromptContext(null, requestedTopK)
                    : limitAuthorizedPromptContext(
                    promptContextAuthorizationService.authorize(event, retrievalPurpose, documents), requestedTopK);
            capturePromptContextAudit(event, retrievalPurpose, limitedAuthorizedPromptContext);
            annotateRagSearchResult(event, searchId, requestedTopK, documents, limitedAuthorizedPromptContext);
            annotatePastRecordCounts(event, searchId, PastRecordCounts.of(request, groups));
            annotatePastRecordScope(event, searchId, scope, sameTargetPaths, requestedTopK, query);
            annotatePastDeniedDecisions(event, searchId,
                    query.deniedDecisions(scope, deniedSince(event), PastDeniedDecisions.LIMIT));
            return limitedAuthorizedPromptContext.documents();
        }
        catch (RuntimeException exception) {
            log.error("[{}] Past record lookup failed", getLayerName(), exception);
            markRagRetrievalUnavailable(event, requestedTopK, exception);
            capturePromptContextAuditFallback(event, retrievalPurpose, requestedTopK,
                    "EXACT_PAST_RECORD_LOOKUP_FAILED", exception);
            return Collections.emptyList();
        }
    }

    /**
     * The user's recent decisions that did not allow, left on the event for the past records block (W5-4): facts only,
     * written by the event's latest search as its counts are.
     */
    private void annotatePastDeniedDecisions(SecurityEvent event, String searchId, List<Document> denied) {
        Map<String, Object> metadata = writableMetadata(event);
        if (metadata == null || Boolean.TRUE.equals(metadata.get("ragTimedOut"))
                || !Objects.equals(searchId, metadata.get("ragSearchId"))) {
            return;
        }
        metadata.put(PastDeniedDecisions.EVENT_METADATA_KEY, PastDeniedDecisions.of(denied).toMetadata());
    }

    /** Where the window of the recent decisions that did not allow starts, on the event clock (W5-4). */
    private static LocalDateTime deniedSince(SecurityEvent event) {
        LocalDateTime at = event.getTimestamp() != null ? event.getLocalTimestamp()
                : LocalDateTime.now(EventTimeZone.get());
        return at.minusDays(PastDeniedDecisions.WINDOW_DAYS);
    }

    private static Map<String, Object> groupMetadata(PastRecordGroup group) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("requestPath", group.path());
        if (group.pathFamily() != null) {
            metadata.put("pathFamily", group.pathFamily());
        }
        return metadata;
    }

    /**
     * The counted facts of the lookup, written only by the event's latest search, as its outcome is. The candidates of
     * an exact lookup are the records it counted, not the ones it read up to its limit (W3-19: one number of past
     * records in the state line and in the counts).
     */
    private void annotatePastRecordCounts(SecurityEvent event, String searchId, PastRecordCounts counts) {
        Map<String, Object> metadata = writableMetadata(event);
        if (metadata == null || Boolean.TRUE.equals(metadata.get("ragTimedOut"))
                || !Objects.equals(searchId, metadata.get("ragSearchId"))) {
            return;
        }
        metadata.put(PastRecordCounts.EVENT_METADATA_KEY, counts.toMetadata());
        metadata.put("ragCandidateDocumentCount", (int) Math.min(Integer.MAX_VALUE, counts.total()));
    }

    /**
     * W6-12: how the past records were chosen, left on the event for the seal: the scope, the paths shown first, the
     * limit, and the store's conditions and order; written by the event's latest search as its counts are.
     */
    private void annotatePastRecordScope(SecurityEvent event, String searchId, PastRecordScope scope,
                                         List<String> firstPaths, int limit, PastRecordQuery query) {
        Map<String, Object> metadata = writableMetadata(event);
        if (metadata == null || Boolean.TRUE.equals(metadata.get("ragTimedOut"))
                || !Objects.equals(searchId, metadata.get("ragSearchId"))) {
            return;
        }
        Map<String, Object> searchScope = new LinkedHashMap<>();
        searchScope.put("userId", scope.userId());
        searchScope.put("retrievalPurpose", scope.retrievalPurpose());
        searchScope.put("actionFamily", scope.actionFamily());
        searchScope.put("excludedSessionIds", scope.excludedSessionIds());
        searchScope.put("firstPaths", firstPaths != null ? List.copyOf(firstPaths) : List.of());
        searchScope.put("limit", limit);
        searchScope.put("filters", query.filters());
        searchScope.put("order", query.order());
        metadata.put("ragSearchScope", searchScope);
    }

    private boolean isLayer1SingleUserRagSearchEnabled() {
        if (!"Layer1".equalsIgnoreCase(getLayerName())) {
            return false;
        }
        TieredStrategyProperties.Layer1 layer1 = tieredStrategyProperties != null
                ? tieredStrategyProperties.getLayer1()
                : null;
        TieredStrategyProperties.Layer1.Rag rag = layer1 != null ? layer1.getRag() : null;
        return rag == null || !rag.isMultiQuerySearchEnabled();
    }

    private boolean isLayer1SupportingRagSearchEnabled() {
        if (!"Layer1".equalsIgnoreCase(getLayerName())) {
            return true;
        }
        TieredStrategyProperties.Layer1 layer1 = tieredStrategyProperties != null
                ? tieredStrategyProperties.getLayer1()
                : null;
        TieredStrategyProperties.Layer1.Rag rag = layer1 != null ? layer1.getRag() : null;
        return rag != null && rag.isSupportingSearchEnabled();
    }

    private void annotateRagSearchPlan(SecurityEvent event, String searchMode, int executedQueryCount, List<String> skippedQueries) {
        Map<String, Object> metadata = writableMetadata(event);
        if (metadata == null) {
            return;
        }
        metadata.put("ragSearchMode", searchMode);
        metadata.put("ragSearchQueryCount", Math.max(0, executedQueryCount));
        metadata.put("ragSkippedQueries", skippedQueries != null ? List.copyOf(skippedQueries) : List.of());
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
        if (isRagBudgetFailure(exception)) {
            markRagRetrievalBudgetExpired(event, requestedTopK);
            return;
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
        metadata.put("requestedDocumentCount", Math.max(0, requestedTopK));
        metadata.put("allowedDocumentCount", 0);
        metadata.put("deniedDocumentCount", 0);
    }

    private boolean isRagBudgetFailure(Exception exception) {
        if (exception == null || exception.getMessage() == null) {
            return false;
        }
        String normalized = exception.getMessage().toLowerCase(Locale.ROOT);
        return normalized.contains("interrupted") || normalized.contains("timed out");
    }

    private void markRagRetrievalBudgetExpired(SecurityEvent event, int requestedTopK) {
        Map<String, Object> metadata = writableMetadata(event);
        if (metadata == null) {
            return;
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
        metadata.put("ragCandidateDocumentCount", 0);
        metadata.put("ragAuthorizedDocumentCount", 0);
        metadata.put("ragDeniedDocumentCount", 0);
        metadata.put("ragPermissionFiltered", false);
        metadata.put("ragRequestedTopK", Math.max(0, requestedTopK));
        metadata.put("requestedDocumentCount", Math.max(0, requestedTopK));
        metadata.put("allowedDocumentCount", 0);
        metadata.put("deniedDocumentCount", 0);
        if (tieredStrategyProperties != null && "Layer1".equalsIgnoreCase(getLayerName())) {
            metadata.put("ragTimeoutMs", Math.max(1L, tieredStrategyProperties.getLayer1().getTimeout().getRagMs()));
        }
        metadata.remove("ragFailureType");
        metadata.remove("ragFailureMessage");
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
        metadata.put("requestedDocumentCount", 0);
        metadata.put("allowedDocumentCount", 0);
        metadata.put("deniedDocumentCount", 0);
    }

    /**
     * Starts a past record search on the event (N-MISS-1 D8). A search after one that timed out keeps that state apart
     * as the earlier retrieval state and writes its own outcome; the id lets only the event's latest search write it.
     */
    private String beginRagSearch(SecurityEvent event) {
        Map<String, Object> metadata = writableMetadata(event);
        if (metadata == null) {
            return null;
        }
        if (Boolean.TRUE.equals(metadata.get("ragTimedOut"))) {
            Object earlier = metadata.get("ragRetrievalState");
            metadata.put("ragEarlierRetrievalState", earlier != null ? String.valueOf(earlier) : "TIMEOUT");
            metadata.put("ragTimedOut", false);
        }
        String searchId = UUID.randomUUID().toString();
        metadata.put("ragSearchId", searchId);
        return searchId;
    }

    private void annotateRagSearchResult(
            SecurityEvent event,
            String searchId,
            int requestedTopK,
            List<Document> candidateDocuments,
            AuthorizedPromptContext authorizedPromptContext) {
        Map<String, Object> metadata = writableMetadata(event);
        if (metadata == null) {
            return;
        }
        // A search whose wait ran out, or that a newer search on the event overtook, does not write its late outcome.
        if (Boolean.TRUE.equals(metadata.get("ragTimedOut")) || !Objects.equals(searchId, metadata.get("ragSearchId"))) {
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
                : (permissionFiltered ? "PERMISSION_FILTER_EXCLUDED" : "ZERO_RESULTS");
        metadata.put("ragSearchExecuted", true);
        metadata.put("ragUnavailable", false);
        metadata.put("ragTimedOut", false);
        metadata.put("ragRetrievalState", retrievalState);
        if (absenceReason != null) {
            metadata.put("ragAbsenceReason", absenceReason);
        } else {
            metadata.remove("ragAbsenceReason");
        }
        metadata.put("ragProjectionState", projectedCount > 0
                ? "PROJECTED"
                : (permissionFiltered ? "PERMISSION_FILTERED_DECLARED" : "ZERO_RESULTS_DECLARED"));
        metadata.put("ragProjectedToFinalPrompt", projectedCount > 0);
        metadata.put("ragStatusProjectedToFinalPrompt", true);
        metadata.put("relatedDocumentCount", projectedCount);
        metadata.put("relatedDocumentsCount", projectedCount);
        metadata.put("ragCandidateDocumentCount", candidateCount);
        metadata.put("ragAuthorizedDocumentCount", authorizedCount);
        metadata.put("ragDeniedDocumentCount", deniedCount);
        metadata.put("ragPermissionFiltered", permissionFiltered);
        metadata.put("ragRequestedTopK", Math.max(0, requestedTopK));
        metadata.put("requestedDocumentCount", authorizedPromptContext != null
                ? authorizedPromptContext.requestedDocumentCount()
                : candidateCount);
        metadata.put("allowedDocumentCount", authorizedCount);
        metadata.put("deniedDocumentCount", deniedCount);
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
        appendQueryPart(query, "action", queryActionFamily(event));
        appendQueryPart(query, "resourceFamily", resourceClassOf(event));
        appendQueryPart(query, "auth",SecuritySemanticNormalizer.normalizeAuthenticationType(
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
        appendQueryPart(query, "action", queryActionFamily(event));
        appendQueryPart(query, "pathFamily", SecuritySemanticNormalizer.pathFamilyOf(
                event != null ? event.getMetadata() : null, targetResource));
        appendQueryPart(query, "browser", event != null && StringUtils.hasText(event.getUserAgent())
                ? SecurityEventEnricher.extractBrowserSignature(event.getUserAgent())
                : null);
        return query.toString().trim();
    }

    private String buildUserBaselineContextQuery(SecurityEvent event) {
        StringBuilder query = new StringBuilder();
        appendQueryPart(query, "user", event != null ? event.getUserId() : null);
        appendQueryPart(query, "purpose", getContextRetrievalPurpose());
        appendQueryPart(query, "action", queryActionFamily(event));
        appendQueryPart(query, "resourceFamily", resourceClassOf(event));
        return query.toString().trim();
    }

    /**
     * The request's action family as the context gives it, so that the query names the action stored with past
     * decisions; omitted when no fact of the request names one.
     */
    private String queryActionFamily(SecurityEvent event) {
        ActionFamily family = ActionFamilyResolver.resolve(event != null ? event.getMetadata() : null).family();
        return family != ActionFamily.UNKNOWN ? family.name() : null;
    }

    /**
     * The resource class from the classification values only (sensitivity first, then type), as in the prompt; a family
     * hint names a business category and is not one of them (W2-10).
     */
    private String resourceClassOf(SecurityEvent event) {
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        if (metadata == null) {
            return null;
        }
        return SecuritySemanticNormalizer.normalizeResourceClass(
                metadata.get("resourceSensitivity"),
                metadata.get("sensitivity"),
                metadata.get("Sensitivity"),
                metadata.get("resourceType"));
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
        // A vector store orders by distance alone (W0-8): ask a margin more (as many again) and choose by the fixed keys
        // of the past record ranking, so that the same input gives the same records at the cut (W3-3).
        int limit = Math.max(1, topK);
        SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(limit * 2)
                .similarityThreshold(similarityThreshold)
                .filterExpression(filterExpression)
                .build();
        List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);
        return documents == null ? List.of() : PastRecordRanking.top(documents, limit);
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

    private Filter.Expression buildBehaviorFilterForUser(
            String userId,
            String retrievalPurpose,
            String resourceId,
            List<String> sessionIds) {
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        List<FilterExpressionBuilder.Op> predicates = new ArrayList<>();
        predicates.add(filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()));
        predicates.add(filterBuilder.eq(VectorDocumentMetadata.USER_ID, userId));
        if (StringUtils.hasText(retrievalPurpose)) {
            predicates.add(filterBuilder.eq(VectorDocumentMetadata.RETRIEVAL_PURPOSE, retrievalPurpose));
        }
        if (StringUtils.hasText(resourceId)) {
            predicates.add(filterBuilder.eq("resourceId", resourceId));
        }
        // The current session's own requests are not past records (W2-8), under any id the session had (P2
        // correction 5). NIN keeps a record without a session, where a not-equal test would drop it.
        if (sessionIds != null && !sessionIds.isEmpty()) {
            predicates.add(filterBuilder.nin(VectorDocumentMetadata.SESSION_ID, sessionIds.toArray()));
        }
        predicates.add(notHeldBack(filterBuilder));
        return combinePredicates(filterBuilder, predicates);
    }

    /**
     * The ids the request's session had before the servlet container replaced its id (P2 correction 5): records
     * written under them are the session's own requests. Empty here; a strategy with the context store reads them.
     */
    protected List<String> previousSessionIds(String sessionId) {
        return List.of();
    }

    /** The request's session id and the ids the session had, the ones whose records are not past records. */
    private List<String> sessionIdsOf(SecurityEvent event) {
        String sessionId = event.getSessionId();
        if (!StringUtils.hasText(sessionId)) {
            return List.of();
        }
        List<String> ids = new ArrayList<>();
        ids.add(sessionId);
        List<String> previous = previousSessionIds(sessionId);
        if (previous != null) {
            previous.stream().filter(StringUtils::hasText).filter(id -> !ids.contains(id)).forEach(ids::add);
        }
        return ids;
    }

    /** A record held back from promotion into the usual behaviour is not a past record (W2-8). */
    private FilterExpressionBuilder.Op notHeldBack(FilterExpressionBuilder filterBuilder) {
        return filterBuilder.nin(VectorDocumentMetadata.LEARNING_STATE, VectorDocumentMetadata.LEARNING_STATE_HELD);
    }

    private Filter.Expression buildBehaviorFilterForOrganization(String organizationId, String retrievalPurpose) {
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        List<FilterExpressionBuilder.Op> predicates = new ArrayList<>();
        predicates.add(filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()));
        predicates.add(filterBuilder.eq(VectorDocumentMetadata.ORGANIZATION_ID, organizationId));
        if (StringUtils.hasText(retrievalPurpose)) {
            predicates.add(filterBuilder.eq(VectorDocumentMetadata.RETRIEVAL_PURPOSE, retrievalPurpose));
        }
        predicates.add(notHeldBack(filterBuilder));
        return combinePredicates(filterBuilder, predicates);
    }

    private Filter.Expression buildBehaviorFilterForSupportingFallback(String retrievalPurpose) {
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        List<FilterExpressionBuilder.Op> predicates = new ArrayList<>();
        predicates.add(filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue()));
        if (StringUtils.hasText(retrievalPurpose)) {
            predicates.add(filterBuilder.eq(VectorDocumentMetadata.RETRIEVAL_PURPOSE, retrievalPurpose));
        }
        predicates.add(notHeldBack(filterBuilder));
        return combinePredicates(filterBuilder, predicates);
    }

    private Filter.Expression combinePredicates(
            FilterExpressionBuilder filterBuilder,
            List<FilterExpressionBuilder.Op> predicates) {
        FilterExpressionBuilder.Op combinedPredicate = predicates.get(0);
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
            // One record once, whichever query found it: its event, else its text (W3-3).
            String key = PastRecordRanking.recordKey(document);
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
        if (promptContextAuditRecorder == null || event == null || authorizedPromptContext == null) {
            return;
        }
        try {
            promptContextAuditRecorder.capture(event, retrievalPurpose, authorizedPromptContext);
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
                    authorizedPromptContext != null
                            ? authorizedPromptContext.requestedDocumentCount()
                            : Math.max(0, requestedTopK),
                    authorizedPromptContext != null ? authorizedPromptContext.allowedDocumentCount() : 0,
                    authorizedPromptContext != null ? authorizedPromptContext.deniedDocumentCount() : 0,
                    getContextRetrievalPurpose(),
                    authorizedPromptContext != null ? authorizedPromptContext.deniedReasons() : List.of());
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
        protected Instant startTime;
        protected Instant lastEventTime;
        protected String ipAddress;
        protected String userAgent;
        protected List<String> recentActions = new ArrayList<>();
        protected int accessFrequency = 0;

        public boolean isValid() {
            return startTime != null;
        }

        /** Minutes from the session's first event to its latest one, both on the event clock. */
        public long getSessionDuration() {
            if (startTime == null) return 0;
            Instant latest = lastEventTime != null && lastEventTime.isAfter(startTime) ? lastEventTime : startTime;
            return Duration.between(startTime, latest).toMinutes();
        }

        public void recordEventTime(Instant eventTime) {
            if (eventTime != null && (lastEventTime == null || eventTime.isAfter(lastEventTime))) {
                lastEventTime = eventTime;
            }
        }

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public Instant getStartTime() { return startTime; }
        public void setStartTime(Instant startTime) { this.startTime = startTime; }

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
        applyOpenAiRuntimeOptions(request, event);
        // W4-7 (inventory 6 bundle 1): the prompt estimate is calibrated for the model the analysis runs on.
        ChatModel analysisModel = analysisChatModel();
        String analysisModelName = analysisModel != null && analysisModel.getDefaultOptions() != null
                ? analysisModel.getDefaultOptions().getModel()
                : null;
        if (StringUtils.hasText(analysisModelName)) {
            request.withParameter("promptEstimationModelHint", analysisModelName.trim());
        }
        StructuredOutputCapability structuredOutputCapability = resolveStructuredOutputCapability(event);
        boolean nativeOutputAllowed = tieredStrategyProperties.getPromptRuntime()
                .isNativeStructuredOutputEnabledForProfile(promptBudgetProfile.profileKey());
        // W4-2: a v20 request that names no model is judged by the chat model the analysis will run on, when the prompt
        // profile allows native structured output; the v19 bundle keeps its own format whatever the model.
        if (runsV20Bundle(event) && nativeOutputAllowed
                && "default".equals(structuredOutputCapability.resolutionSource())) {
            StructuredOutputCapability selected = capabilityOf(analysisModel);
            if (selected != null) {
                structuredOutputCapability = selected;
            }
        }
        StructuredOutputMode structuredOutputMode = resolveStructuredOutputMode(event, structuredOutputCapability);
        if (!nativeOutputAllowed && structuredOutputMode == StructuredOutputMode.NATIVE_STRUCTURED
                && !explicitStructuredOutputMode(event)) {
            // A prompt profile with native structured output turned off keeps the schema in the system text.
            structuredOutputMode = StructuredOutputMode.VALIDATED_CONVERTER;
        }
        request.withParameter("structuredOutputMode", structuredOutputMode.name());
        // W4-2: a v20 request with native structured output asks the provider to enforce the output contract v3; the
        // v19 bundle keeps its own format, and without native output the system text states the schema.
        if (structuredOutputMode == StructuredOutputMode.NATIVE_STRUCTURED && runsV20Bundle(event)) {
            request.withParameter(ExecutionContext.OUTPUT_SCHEMA, SecurityDecisionOutputContract.providerSchema());
        }
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());
        request.withParameter("structuredOutputValidationMaxAttempts", 1);
        request.withParameter("strictResponsePostprocessing", true);
        request.withParameter("pipelineFailurePolicy", PipelineFailurePolicy.PROPAGATE_ERROR.name());
        // W4-6: the platform's determinism settings; the request's own temperature and seed never reach the call.
        // N-OUT-1 (G1-8): the layer's tier, so a configured layer model applies.
        request.withParameter("platformAnalysisTier", analysisTier());
        TieredStrategyProperties.Determinism determinism = tieredStrategyProperties.getDeterminism();
        if (determinism != null && determinism.getTemperature() != null) {
            request.withParameter("platformDeterminismTemperature", determinism.getTemperature());
        }
        if (determinism != null && determinism.getSeed() != null) {
            request.withParameter("platformDeterminismSeed", determinism.getSeed());
        }
        // W4-5: the response check enforces the minimum action rules in enforce mode, with the host's settings.
        request.withParameter("minimumActionMode", minimumActionMode);
        request.withParameter("minimumActionSettings", minimumActionSettings);
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

    /**
     * The structured output capability of the chat model the model selection picks for a request that names no model
     * (the same context the security decision call builds: no tier, no model): native when its provider enforces
     * schemas and its options can carry one; null when it cannot be told.
     */
    /** The chat model the analysis will run on, selected on this layer's tier; null when it cannot be selected. */
    private ChatModel analysisChatModel() {
        ModelSelectionStrategy selection = modelSelectionStrategy != null ? modelSelectionStrategy.get() : null;
        if (selection == null) {
            return null;
        }
        try {
            ExecutionContext selectionContext = ExecutionContext.from(new Prompt(""));
            selectionContext.setTier(analysisTier());
            return selection.selectModel(selectionContext);
        } catch (RuntimeException e) {
            log.error("[{}] The chat model of the analysis could not be selected", getLayerName(), e);
            return null;
        }
    }

    private StructuredOutputCapability capabilityOf(ChatModel model) {
        if (model == null) {
            return null;
        }
        String provider = ChatModelProviders.providerOf(model);
        if (provider == null) {
            return null;
        }
        StructuredOutputCapability known = structuredOutputCapabilityRegistry.resolve(null, provider, true);
        boolean carriesSchema = model.getDefaultOptions() instanceof StructuredOutputChatOptions;
        return new StructuredOutputCapability(known.providerFamily(), known.nativeStructuredSupported() && carriesSchema,
                true, "selectedChatModel");
    }

    /** N-OUT-1 (G1-8): the model tier of this layer's analysis: 2 for the second layer, 1 otherwise. */
    protected int analysisTier() {
        return "Layer2".equalsIgnoreCase(getLayerName()) ? 2 : 1;
    }

    private static boolean explicitStructuredOutputMode(SecurityEvent event) {
        return event != null && event.getMetadata() != null
                && StructuredOutputMode.fromValue(event.getMetadata().get("structuredOutputMode"), null) != null;
    }

    protected StructuredOutputCapability resolveStructuredOutputCapability(SecurityEvent event) {
        String modelHint = null;
        String providerHint = null;
        if (event != null && event.getMetadata() != null) {
            modelHint = firstNonBlank(
                    event.getMetadata().get("requestedModelId"),
                    event.getMetadata().get("preferredModel"),
                    event.getMetadata().get("runtimeModelId"));
            providerHint = firstNonBlank(
                    event.getMetadata().get("selectedModelProvider"),
                    event.getMetadata().get("providerResponseModel"));
        }
        return structuredOutputCapabilityRegistry.resolve(modelHint, providerHint, true);
    }

    protected void applySecurityDecisionRuntimeTelemetry(
            SecurityDecision decision,
            SecurityDecisionResponse pipelineResponse) {
        if (decision == null || pipelineResponse == null) {
            return;
        }
        // W4-3: the reason codes the model gave stay with the decision, as the model gave them.
        if (pipelineResponse.getReasonCodes() != null && !pipelineResponse.getReasonCodes().isEmpty()) {
            decision.setReasonCodes(List.copyOf(pipelineResponse.getReasonCodes()));
        }
        if (pipelineResponse.getFieldProvenance() != null
                && !pipelineResponse.getFieldProvenance().isEmpty()) {
            decision.setFieldProvenance(Map.copyOf(pipelineResponse.getFieldProvenance()));
        }
        Map<String, Object> metadata = pipelineResponse.getAllMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return;
        }
        Boolean llmDecisionPresent = booleanValue(metadata.get("llmDecisionPresent"));
        boolean rawExecutionFailed = Boolean.FALSE.equals(booleanValue(metadata.get("rawExecutionSucceeded")));
        boolean fallbackApplied = Boolean.TRUE.equals(booleanValue(metadata.get("securityDecisionFallbackApplied")))
                || Boolean.TRUE.equals(booleanValue(metadata.get("securityDecisionParsingFallbackApplied")))
                || Boolean.TRUE.equals(booleanValue(metadata.get("syntheticSecurityDecisionApplied")));
        String failureCategory = normalizeTelemetryFailureCategory(firstNonBlank(
                metadata.get("structuredOutputFailureCategory"),
                metadata.get("securityDecisionParseFailureCategory"),
                metadata.get("decisionFailureCategory")));
        if (fallbackApplied && !rawExecutionFailed) {
            String responseFallbackCategory = firstNonBlank(
                    metadata.get("securityDecisionFallbackReason"),
                    failureCategory,
                    "ACTION_FORMAT_INVALID");
            decision.setLlmDecisionPresent(Boolean.FALSE.equals(llmDecisionPresent) ? false : true);
            decision.setTechnicalFallbackApplied(false);
            decision.setResponseActionFallbackApplied(true);
            decision.setResponseActionFallbackCategory(responseFallbackCategory);
            decision.setResponseActionFallbackReason(
                    "Security decision response action was repaired: " + responseFallbackCategory);
            decision.setResponseActionFallbackAction(firstNonBlank(
                    metadata.get("securityDecisionFallbackAction"),
                    decision.getAction() != null ? decision.getAction().name() : null));
            return;
        }
        // N-OUT-1 (G1-3): a response whose JSON broke but whose action was read is the model's decision; the format
        // defect stays in the telemetry's parse failure category.
        boolean formatOnlyDefect = !fallbackApplied && !rawExecutionFailed && !Boolean.FALSE.equals(llmDecisionPresent)
                && ("MALFORMED_JSON".equals(failureCategory) || "TRUNCATED_JSON".equals(failureCategory));
        if (!formatOnlyDefect && (Boolean.FALSE.equals(llmDecisionPresent) || rawExecutionFailed || fallbackApplied
                || failureCategory != null)) {
            decision.setLlmDecisionPresent(false);
            decision.setTechnicalFallbackApplied(true);
            decision.setTechnicalFallbackCategory(firstNonBlank(
                    failureCategory,
                    metadata.get("securityDecisionFallbackReason"),
                    metadata.get("securityDecisionRawExecutionFailureClass"),
                    decision.getTechnicalFallbackCategory(),
                    "TECHNICAL_FALLBACK"));
            decision.setTechnicalFallbackReason(firstNonBlank(
                    metadata.get("securityDecisionRawExecutionFailureMessage"),
                    metadata.get("securityDecisionFallbackReason"),
                    metadata.get("decisionFailureMessage"),
                    decision.getTechnicalFallbackReason(),
                    "Security decision was produced by fail-closed fallback."));
            decision.setTechnicalFallbackAction(firstNonBlank(
                    metadata.get("securityDecisionFallbackAction"),
                    metadata.get("decisionFailureTechnicalFallbackAction"),
                    decision.getTechnicalFallbackAction(),
                    decision.getAction() != null ? decision.getAction().name() : null));
            return;
        }
        decision.setLlmDecisionPresent(true);
        preserveModelReasoning(decision);
        decision.setTechnicalFallbackApplied(false);
    }

    /**
     * Produces the final operator-facing explanation from the same canonical
     * evidence that constrains enforcement. Historical RAG facts remain model
     * input, but cannot be restated as current request facts.
     */
    protected void applyCanonicalDecisionReasoning(
            SecurityDecision decision,
            SecurityEvent event,
            List<Document> relatedDocuments) {
        if (decision == null || event == null || event.getMetadata() == null) {
            return;
        }

        // W4-3 (Q-57 decision 2): a v20 decision keeps the model's reason and reason codes; only v19 fixes sentences.
        if (runsV20Bundle(event)) {
            return;
        }
        Map<String, Object> metadata = event.getMetadata();
        ZeroTrustAction finalAction = decision.resolveAutonomousAction();
        if (finalAction == ZeroTrustAction.ALLOW) {
            boolean personalBaselineEstablished = Boolean.TRUE.equals(
                    booleanValue(metadata.get("personalBaselineEstablished")))
                    || Boolean.TRUE.equals(booleanValue(metadata.get("learningPersonalBaselineEstablished")));
            if (hasSameResourceAuthorizedRag(event, relatedDocuments)) {
                setCanonicalReasoning(
                        decision,
                        personalBaselineEstablished
                                ? SAME_RESOURCE_RAG_ESTABLISHED_BASELINE_ALLOW_REASONING
                                : SAME_RESOURCE_RAG_ALLOW_REASONING);
            } else if (claimsSameResourceRag(decision.getReasoning())) {
                // The past records decide it too (W2-8): without a record of the same target the claim is replaced.
                setCanonicalReasoning(
                        decision,
                        personalBaselineEstablished
                                ? ESTABLISHED_BASELINE_ALLOW_REASONING
                                : LIMITED_BASELINE_ALLOW_REASONING);
            } else if (!personalBaselineEstablished && claimsEstablishedBaseline(decision.getReasoning())) {
                // The canonical facts decide the baseline: an established-baseline claim without one is replaced.
                setCanonicalReasoning(decision, LIMITED_BASELINE_ALLOW_REASONING);
            }
        }
    }

    private boolean claimsSameResourceRag(String reasoning) {
        return reasoning != null && reasoning.toLowerCase(Locale.ROOT).contains("relevant to the same resource");
    }

    private boolean claimsEstablishedBaseline(String reasoning) {
        return reasoning != null && reasoning.toLowerCase(Locale.ROOT).contains("baseline is established");
    }

    private void setCanonicalReasoning(SecurityDecision decision, String canonicalReasoning) {
        preserveModelReasoning(decision);
        Map<String, String> provenance = decision.getFieldProvenance() == null
                ? new LinkedHashMap<>()
                : new LinkedHashMap<>(decision.getFieldProvenance());
        decision.setReasoning(canonicalReasoning);
        provenance.put("reasoning", "PLATFORM_CANONICAL");
        decision.setFieldProvenance(Map.copyOf(provenance));
    }

    private void preserveModelReasoning(SecurityDecision decision) {
        Map<String, String> provenance = decision.getFieldProvenance() == null
                ? Map.of()
                : decision.getFieldProvenance();
        boolean modelReasoning = "MODEL".equalsIgnoreCase(provenance.get("reasoning"))
                || (provenance.get("reasoning") == null
                        && Boolean.TRUE.equals(decision.getLlmDecisionPresent()));
        if (modelReasoning && !StringUtils.hasText(decision.getLlmReasoning())) {
            decision.setLlmReasoning(decision.getReasoning());
        }
    }

    private boolean hasSameResourceAuthorizedRag(
            SecurityEvent event,
            List<Document> relatedDocuments) {
        Map<String, Object> metadata = event.getMetadata();
        if (!Boolean.TRUE.equals(booleanValue(metadata.get("ragProjectedToFinalPrompt")))
                || relatedDocuments == null
                || relatedDocuments.isEmpty()) {
            return false;
        }
        // The same computation as the prompt's RagRelevance: the path template and the target, not the method.
        return PastRecordRelevance.SAME_RESOURCE.equals(PastRecordRelevance.relevance(
                PastRecordRelevance.Subject.ofRequest(metadata, event.getDescription()),
                relatedDocuments.stream()
                        .filter(Objects::nonNull)
                        .map(document -> PastRecordRelevance.Subject.ofRecord(document.getMetadata(), document.getText()))
                        .toList()));
    }

    private Boolean booleanValue(Object value) {
        return TruthValues.parse(value);
    }

    private String normalizeTelemetryFailureCategory(String value) {
        String text = firstNonBlank(value);
        if (text == null || "NONE".equalsIgnoreCase(text)) {
            return null;
        }
        return text;
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
        copyRuntimeSelectionOption(metadata, request, "openAiReasoningEffort");
        copyRuntimeSelectionOption(metadata, request, "openAiVerbosity");
    }

    protected void applyOpenAiRuntimeOptions(SecurityDecisionRequest request, SecurityEvent event) {
        if (request == null) {
            return;
        }
        String reasoningEffort = resolveOpenAiReasoningEffort();
        if (StringUtils.hasText(reasoningEffort)) {
            request.withParameter("openAiReasoningEffort", reasoningEffort.trim());
        }
        String verbosity = resolveOpenAiVerbosity();
        if (StringUtils.hasText(verbosity)) {
            request.withParameter("openAiVerbosity", verbosity.trim());
        }
        int maxOutputTokens = resolveConfiguredMaxOutputTokens();
        if (maxOutputTokens > 0) {
            request.withParameter("platformSecurityDecisionMaxTokens", maxOutputTokens);
        }
        // P3-EXTRA-9: the layer's model call limit bounds the provider call, which waits on its own executor; waiting
        // on the pipeline cannot bound it, since the pipeline runs on the calling thread.
        long callTimeoutMs = resolveConfiguredCallTimeoutMs();
        if (callTimeoutMs > 0) {
            request.withParameter("platformSecurityDecisionCallTimeoutMs", callTimeoutMs);
        }
    }

    /** Layer 1's model call limit; Layer 2 sets none of its own. */
    protected long resolveConfiguredCallTimeoutMs() {
        String layerName = getLayerName();
        if (layerName != null && layerName.toLowerCase(Locale.ROOT).contains("layer2")) {
            return 0L;
        }
        return tieredStrategyProperties != null && tieredStrategyProperties.getLayer1() != null
                && tieredStrategyProperties.getLayer1().getTimeout() != null
                ? tieredStrategyProperties.getLayer1().getTimeout().getLlmMs()
                : 0L;
    }

    protected int resolveConfiguredMaxOutputTokens() {
        String layerName = getLayerName();
        if (layerName != null && layerName.toLowerCase(Locale.ROOT).contains("layer2")) {
            return tieredStrategyProperties != null && tieredStrategyProperties.getLayer2() != null
                    ? tieredStrategyProperties.getLayer2().getMaxOutputTokens()
                    : 0;
        }
        return tieredStrategyProperties != null && tieredStrategyProperties.getLayer1() != null
                ? tieredStrategyProperties.getLayer1().getMaxOutputTokens()
                : 0;
    }

    protected String resolveOpenAiReasoningEffort() {
        String layerName = getLayerName();
        if (layerName != null && layerName.toLowerCase(Locale.ROOT).contains("layer2")) {
            return tieredStrategyProperties != null && tieredStrategyProperties.getLayer2() != null
                    ? tieredStrategyProperties.getLayer2().getOpenAiReasoningEffort()
                    : null;
        }
        return tieredStrategyProperties != null && tieredStrategyProperties.getLayer1() != null
                ? tieredStrategyProperties.getLayer1().getOpenAiReasoningEffort()
                : null;
    }

    protected String resolveOpenAiVerbosity() {
        String layerName = getLayerName();
        if (layerName != null && layerName.toLowerCase(Locale.ROOT).contains("layer2")) {
            return tieredStrategyProperties != null && tieredStrategyProperties.getLayer2() != null
                    ? tieredStrategyProperties.getLayer2().getOpenAiVerbosity()
                    : null;
        }
        return tieredStrategyProperties != null && tieredStrategyProperties.getLayer1() != null
                ? tieredStrategyProperties.getLayer1().getOpenAiVerbosity()
                : null;
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

    protected PromptBudgetProfile resolvePromptBudgetProfile(SecurityEvent event) {
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
        PromptRuntimeTelemetrySupport.modelOutputTextKeys().forEach(metadata::remove);
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
            copyLayerScopedTimingTelemetry(metadata, telemetry);
            metadata.put("promptRuntimeTelemetryLinked", true);
            metadata.put("promptRuntimeTelemetryLayer", getLayerName());
        }
        if (pipelineResponse.getEvidenceRefs() != null && !pipelineResponse.getEvidenceRefs().isEmpty()) {
            metadata.put("evidenceRefs", List.copyOf(pipelineResponse.getEvidenceRefs()));
        }
        Object evidenceRefs = responseMetadata.get("evidenceRefs");
        if (evidenceRefs != null && !metadata.containsKey("evidenceRefs")) {
            metadata.put("evidenceRefs", evidenceRefs);
        }
        copyPromptTextIfPresent(responseMetadata, metadata, "systemPrompt");
        copyPromptTextIfPresent(responseMetadata, metadata, "userPrompt");
        copyPromptTextIfPresent(responseMetadata, metadata, "rawSystemPrompt");
        copyPromptTextIfPresent(responseMetadata, metadata, "rawUserPrompt");
        // N-OUT-1 (G1-2): the model's raw answers travel like the prompt texts.
        for (String key : PromptRuntimeTelemetrySupport.modelOutputTextKeys()) {
            copyPromptTextIfPresent(responseMetadata, metadata, key);
        }
        // W6-6: this layer's model call stays in the record when the next layer clears the telemetry above.
        PromptRuntimeTelemetrySupport.appendModelCallStage(metadata, getLayerName());
        if (promptContextAuditRecorder != null && hasPromptLineage(metadata)) {
            promptContextAuditRecorder.enrich(event);
        }
    }

    private void copyLayerScopedTimingTelemetry(Map<String, Object> target, Map<String, Object> telemetry) {
        if (target == null || telemetry == null || telemetry.isEmpty()) {
            return;
        }
        String layer = getLayerName();
        if (!StringUtils.hasText(layer)) {
            return;
        }
        String prefix = layer.trim().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "");
        if (!StringUtils.hasText(prefix)) {
            return;
        }
        // W4-7 (inventory 6 bundle 30): one name for the call time; the layer copy keeps the first layer's time.
        copyLayerScopedTiming(target, telemetry, prefix, "providerCallMs", "ProviderCallMs");
        copyLayerScopedTiming(target, telemetry, prefix, "providerCallTimeoutMs", "ProviderCallTimeoutMs");
        copyLayerScopedTiming(target, telemetry, prefix, "providerModelSelectionMs", "ProviderModelSelectionMs");
        copyLayerScopedTiming(target, telemetry, prefix, "providerChatClientBuildMs", "ProviderChatClientBuildMs");
        copyLayerScopedTiming(target, telemetry, prefix, "providerPromptSpecPrepareMs", "ProviderPromptSpecPrepareMs");
        copyLayerScopedTiming(target, telemetry, prefix, "providerThrottleWaitMs", "ProviderThrottleWaitMs");
        copyLayerScopedValue(target, telemetry, prefix, "providerCallExceededTimeout", "ProviderCallExceededTimeout");
        copyLayerScopedValue(target, telemetry, prefix, "providerCallFailureCategory", "ProviderCallFailureCategory");
        copyLayerScopedTiming(target, telemetry, prefix, "providerResponseMetadataMs", "ProviderResponseMetadataMs");
        copyLayerScopedTiming(target, telemetry, prefix, "pipelinePromptGenerationMs", "PromptGenerationMs");
        copyLayerScopedTiming(target, telemetry, prefix, "promptBuildLatencyMs", "PromptBuildMs");
        copyLayerScopedTiming(target, telemetry, prefix, "securityDecisionParseMs", "ParseMs");
        copyLayerScopedTiming(target, telemetry, prefix, "responseExtractMs", "ResponseExtractMs");
        copyLayerScopedTiming(target, telemetry, prefix, "actualPromptTokens", "ActualPromptTokens");
    }


    private void copyLayerScopedValue(
            Map<String, Object> target,
            Map<String, Object> telemetry,
            String prefix,
            String sourceKey,
            String targetSuffix) {
        Object value = telemetry.get(sourceKey);
        if (value != null) {
            target.put(prefix + targetSuffix, value);
        }
    }
    private void copyLayerScopedTiming(
            Map<String, Object> target,
            Map<String, Object> telemetry,
            String prefix,
            String sourceKey,
            String targetSuffix) {
        Object value = telemetry.get(sourceKey);
        if (value != null) {
            target.put(prefix + targetSuffix, value);
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
