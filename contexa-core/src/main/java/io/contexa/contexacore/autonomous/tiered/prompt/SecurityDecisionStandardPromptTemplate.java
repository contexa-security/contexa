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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleProvider;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyRuntimePack;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackSnapshot;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.*;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import lombok.Getter;
import lombok.Setter;
import org.springframework.ai.document.Document;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SecurityDecisionStandardPromptTemplate extends AbstractStandardPromptTemplate<SecurityDecisionResponseLite> {

    private static final String STRUCTURED_PROMPT_CACHE_KEY = "securityDecisionStructuredPrompt";

    public static final String STANDARD_TEMPLATE_KEY = "SecurityDecisionStandard";
    public static final PromptGovernanceDescriptor SECURITY_DECISION_PROMPT_GOVERNANCE =
            new PromptGovernanceDescriptor(
                    "cortex.security-decision",
                    STANDARD_TEMPLATE_KEY,
                    "2026.10.16-v19.19",
                    "CORTEX_PROMPT_CONTRACT_V2",
                    PromptReleaseStatus.PRODUCTION,
                    "contexa-cortex-core",
                    "P5-GOLD-2026-10-16",
                    "protocol-938648df",
                    null,
                    "Zero Trust runtime decision prompt in the v19 format with computed facts: one action family vocabulary with its source (W2-1), the host's URL template as the path family (W2-2), one usual-behaviour view with its evidence grade (W2-3), and the device as one dimension with networks in one form and the host's network zone (W2-4), the host's company records as structured facts with the resource author's words apart from its business label (W2-6), and the approval facts as they hold at the request time with a missing approval status no longer read as a missing lineage (W2-5), and each past record related to the request by the URL template and the target it names, the request's own session left out of the past records (W2-8), and each distinct past record of one protected method on its own line with only copies of one record sharing a line (W2-2 correction), and a change of device or of network within the session stated against the client the session first came from, in place of the binding-hash mismatch no code produced (W2-14), and the observed work pattern from the host's access history only, a missing history stated rather than the work profile repeated (W2-12); with the render unchanged: the budget profiles fitted to the v20 prompts (TO-5; after P4, W4-2, W4-4), the verifier contracts left the bundle (R4-B9), a 600 ms interactive past record wait (P3-EXTRA-4), golden inputs from the P3 gate measurement (P2-CHANGE-25), the response checker's fallback to the contract's action after a failed retry and the floor each minimum action rule names (N-OUT-1, W4-5, N-P3-1), its label checks for v19 prompts only (W4-8), a golden render of the sealed baselines (N-GOLD-1); P5 drew the learning facts anew and the bundle declares its vocabulary (W5-4, W5-7, W5-9, W5-10); the login classifier source changed, the render unchanged (W5-10 D6)",
                    List.of(
                            "STRICT_JSON_SCHEMA",
                            "LOW_TEMPERATURE_SECURITY_DECISION",
                            "EVIDENCE_ONLY_RETRIEVAL",
                            "MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI"
                    ),
                    SecurityDecisionStandardPromptTemplate.class.getName());

    /**
     * The v20 bundle (W3-16): the dictionary user prompt of P3, shipped next to the v19 bundle and run only when a
     * selector chooses it. W3-18 changed its past records ({@code 2026.10.12-v20.2}), W3-19 gave each fact two lines
     * state one source ({@code 2026.10.13-v20}), P3 extra 12 drew the fact IDs of every cited block
     * ({@code 2026.10.13-v20.2}), W3-5 left out the items the user removed (Q-61, Q-73, {@code 2026.10.13-v20.3}) and
     * the W3-19 notations that repeated one source were left out (Q-79, {@code 2026.10.13-v20.4}) and the dictionary
     * form of the differences from the usual took a value without differences that states the closest past record
     * (P3 extra 39, {@code 2026.10.13-v20.5}), the fact lines left out the instructions their producers write with
     * the facts (TO-1 to TO-3, Q-84, Q-85) and the dictionary's UNKNOWN form took the renderer's words (P3 extra
     * 37, {@code 2026.10.13-v20.6}), the bundle got its own system text (TO-4, W4-1 brought forward,
     * {@code 2026.10.13-v20.7}), the budget profiles were fitted to its prompts (TO-5, {@code 2026.10.13-v20.8})
     * and the facts and boundaries of the learning stage and of covered work were made clear (LU-1 to LU-4,
     * {@code 2026.10.14-v20.9}, then the differences from a baseline not established yet,
     * {@code 2026.10.14-v20.10}), the server-issued trusted signal left the dictionary and the system text (R4-T,
     * {@code 2026.10.14-v20.11}), the verifier contracts left the bundle (R4-B9, {@code 2026.10.14-v20.12}) and the
     * P3 extra work changed the wait, two session values and an example (P3-EXTRA-4, 13, 18, 34,
     * {@code 2026.10.14-v20.13}), the golden inputs came from the P3 gate measurement ({@code 2026.10.14-v20.14}) and
     * P4 wrote the output contract block, the minimum action rules and the boundaries on prompt facts (W4-2, W4-3,
     * W4-4, N-RULE-1, {@code 2026.10.14-v20.15}) and the answers to the external evaluation changed its system text,
     * dictionary and render (Q-87: N-FRIC-1, N-P3-1, N-WORD-1, N-UID-1, {@code 2026.10.15-v20.16}) and the response
     * checker reads the facts the prompt was drawn from (W4-8, {@code 2026.10.15-v20.17}) and its golden render draws
     * the baseline of the sealed decisions (N-GOLD-1, {@code 2026.10.15-v20.18}) and its covered-work boundary says an
     * unrecorded decision time does not prevent covered work (N-WORD-2, {@code 2026.10.15-v20.19}) and P5 drew the
     * learning and memory facts anew and declared the vocabulary (W5-4, W5-7, W5-9, W5-10, {@code 2026.10.15-v20.20})
     * and its usual login line takes a login of two methods (W5-10 D6, {@code 2026.10.16-v20.21}) and a login holding a
     * usual login and more is no departure (P5-변경-17, {@code 2026.10.16-v20.22}) and the golden render draws the P5 gate
     * measurement (two-method logins included), so it ships as {@code 2026.10.16-v20.23}; the
     * earlier v20 manifests stay as the records of what they were. It is not approved for runtime and not evaluated yet (version management 10: evaluation and
     * approval come in P6 to P8).
     */
    public static final PromptGovernanceDescriptor SECURITY_DECISION_V20_PROMPT_GOVERNANCE =
            new PromptGovernanceDescriptor(
                    "cortex.security-decision",
                    STANDARD_TEMPLATE_KEY,
                    "2026.10.16-v20.23",
                    "CORTEX_PROMPT_CONTRACT_V3",
                    PromptReleaseStatus.DRAFT,
                    "contexa-cortex-core",
                    "P5-GOLD-2026-10-16",
                    "NOT-EVALUATED",
                    "2026.10.16-v19.19",
                    "Zero Trust runtime decision prompt in the v20 dictionary format (W3-1 to W3-19, TO-1 to TO-5, LU-1 to LU-4, R4-T, R4-B9 and the P3 extra work; the 2026.10.14-v20.14 manifest lists them), with the P4 system text: the minimum action rules the host turned on, each naming its floor, P1 and P2 a challenge and P3 a review because a verified user does not supply a missing record (W4-4, N-P3-1); the boundaries and evidence rules on prompt facts only, the BLOCK boundary naming what is observed and a repeat, a new target or a large volume no risk by itself (N-RULE-1, N-WORD-1, N-FRIC-1); the output contract v3 block with the meaning and the cited line of every reason code, MATERIAL_MISSING_EVIDENCE citing the ID the UNKNOWN line gives each missing fact (W4-2, N-UID-1); no fixed reason sentences (W4-3). An approval without a decision time says what was not checked (N-WORD-1). The response checker falls back to the contract's action after a failed retry (N-OUT-1, W4-5) and checks the boundaries, the reason claims and the reason codes on the facts the prompt was drawn from (W4-8). The golden render draws the baseline the sealed prompts state (N-GOLD-1). An approval or ticket whose decision time is not recorded does not prevent covered work (N-WORD-2). The budget profiles fitted to these prompts the TO-5 way. P5 drew the learning and memory facts anew: the non-allowed records (W5-4), one protection of what is learned (W5-9), and baseline statistics v2: each dimension with its counts, days and first and last times, first seen apart from rare, one denominator, maturity by dates and convergence with the reasons it misses, one request rate, logins of two factors kept, the organization usual by frequency, the peer comparison with the group size and the tenant in the baseline key (W5-10); the bundle declares its vocabulary (W5-7). Logins of two methods are kept and one holding a usual login is no departure (W5-10 D6); P3 takes only a floor the facts can meet (N-CONF-1).",
                    List.of(
                            "STRICT_JSON_SCHEMA",
                            "LOW_TEMPERATURE_SECURITY_DECISION",
                            "EVIDENCE_ONLY_RETRIEVAL",
                            "MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI"
                    ),
                    SecurityDecisionStandardPromptTemplate.class.getName());

    private final SecurityDecisionPromptSections promptSections;

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer) {
        this(eventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                null);
    }

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer,
            PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver) {
        this(eventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                promptGovernanceDescriptorResolver,
                PromptRuntimeGovernanceRuleProvider.none());
    }

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer,
            PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver,
            PromptRuntimeGovernanceRuleProvider promptRuntimeGovernanceRuleProvider) {
        this(eventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                promptGovernanceDescriptorResolver,
                promptRuntimeGovernanceRuleProvider,
                null);
    }

    /**
     * @param promptBundleSelector chooses the bundle each request runs (W3-16); null for the configured bundle
     *                             ({@code contexa.security.tiered.prompt-bundle.active})
     */
    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer,
            PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver,
            PromptRuntimeGovernanceRuleProvider promptRuntimeGovernanceRuleProvider,
            PromptBundleSelector promptBundleSelector) {
        this(new SecurityDecisionPromptSections(
                eventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                promptBundleSelector,
                promptGovernanceDescriptorResolver,
                promptRuntimeGovernanceRuleProvider));
    }

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties) {
        this(eventEnricher, tieredStrategyProperties, null, null);
    }
    /** W4-4: the host's minimum action rule settings the v20 system text states (dictionary 6). */
    public void setMinimumActionSettings(MinimumActionRules.Settings settings) {
        promptSections.setMinimumActionSettings(settings);
    }

    public SecurityDecisionStandardPromptTemplate(SecurityDecisionPromptSections promptSections) {
        super(SecurityDecisionResponseLite.class);
        this.promptSections = promptSections;
    }

    /**
     * The system prompt with the output format of the bundle the event runs (TO-4): the v20 bundle's wording check names
     * the dictionary's facts.
     */
    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String domainPrompt = generateDomainSystemPrompt(request, systemMetadata);
        String formatInstructions = shouldIncludeFormatInstructions(request)
                ? SecurityDecisionContractSectionBuilder.formatInstructions(v20Bundle(request)) : null;
        return assembleSystemPrompt(domainPrompt, formatInstructions, null);
    }

    /** Whether the request's event runs the v20 bundle; its bundle is fixed on the event by its first prompt. */
    private boolean v20Bundle(AIRequest<? extends DomainContext> request) {
        return request instanceof SecurityDecisionRequest securityDecisionRequest
                && securityDecisionRequest.getContext() != null
                && promptBundle(securityDecisionRequest.getContext().getSecurityEvent()).layout()
                == SecurityDecisionPromptBundles.UserPromptLayout.V20_BLOCKS;
    }

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildStructuredPrompt(request).systemText();
    }

    @Override
    protected boolean shouldIncludeFormatInstructions(AIRequest<? extends DomainContext> request) {
        return resolveStructuredOutputMode(request) != StructuredOutputMode.NATIVE_STRUCTURED;
    }

    @Override
    protected String getFormatInstructions() {
        return SecurityDecisionContractSectionBuilder.formatInstructions();
    }

    @Override
    protected boolean shouldIncludeSystemMetadata(AIRequest<? extends DomainContext> request) {
        return false;
    }

    @Override
    public TemplateType getSupportedType() {
        return SecurityDecisionRequest.TEMPLATE_TYPE;
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        return buildStructuredPrompt(request).userText();
    }

    @Override
    public PromptGovernanceDescriptor getPromptGovernanceDescriptor() {
        return SECURITY_DECISION_PROMPT_GOVERNANCE;
    }

    /** The bundle the event runs, fixed on the event for its later prompts (W3-16, W3-18). */
    public SecurityDecisionPromptBundles.Bundle promptBundle(SecurityEvent event) {
        return promptSections.bundleOf(event);
    }

    @Override
    public PromptExecutionMetadata buildPromptExecutionMetadata(
            AIRequest<? extends DomainContext> request,
            String systemPrompt,
            String userPrompt) {
        StructuredPrompt structuredPrompt = buildStructuredPrompt(request);
        if (structuredPrompt.executionMetadata() != null) {
            PromptExecutionMetadata baseMetadata = structuredPrompt.executionMetadata();
            return PromptGovernanceSupport.buildExecutionMetadata(
                    baseMetadata.governanceDescriptor(),
                    baseMetadata.budgetProfile(),
                    baseMetadata.sectionSet(),
                    baseMetadata.omittedSections(),
                    baseMetadata.omissionLedger(),
                    baseMetadata.duplicationInventory(),
                    baseMetadata.promptEvidenceCompleteness(),
                    estimationModelHint(request),
                    systemPrompt,
                    userPrompt,
                    systemPrompt,
                    userPrompt,
                    baseMetadata.promptCompressionLedger(),
                    baseMetadata.supplementalMetadata());
        }
        return PromptGovernanceSupport.buildExecutionMetadata(
                getPromptGovernanceDescriptor(),
                estimationModelHint(request),
                systemPrompt,
                userPrompt);
    }

    public StructuredPrompt buildStructuredPrompt(
            SecurityEvent event,
            SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments) {
        return promptSections.buildStructuredPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments);
    }

    public StructuredPrompt buildStructuredPrompt(
            SecurityEvent event,
            SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments,
            PromptBudgetProfile budgetProfile) {
        return promptSections.buildStructuredPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments, budgetProfile);
    }

    public StructuredPrompt buildStructuredPrompt(
            SecurityEvent event,
            SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments,
            PromptBudgetProfile budgetProfile,
            StructuredOutputMode structuredOutputMode) {
        return promptSections.buildStructuredPrompt(
                event,
                sessionContext,
                behaviorAnalysis,
                relatedDocuments,
                budgetProfile,
                structuredOutputMode);
    }

    public String buildPrompt(
            SecurityEvent event,
            SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments) {
        return promptSections.buildPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments);
    }

    private StructuredPrompt buildStructuredPrompt(AIRequest<? extends DomainContext> request) {
        StructuredPrompt cached = request.getParameter(STRUCTURED_PROMPT_CACHE_KEY, StructuredPrompt.class);
        if (cached != null) {
            return cached;
        }

        if (!(request instanceof SecurityDecisionRequest securityDecisionRequest)) {
            throw new IllegalArgumentException("SecurityDecisionStandardPromptTemplate supports only SecurityDecisionRequest");
        }

        SecurityDecisionContext context = securityDecisionRequest.getContext();
        PromptBudgetProfile budgetProfile = PromptBudgetProfile.fromKey(
                securityDecisionRequest.getParameter("promptBudgetProfile", String.class),
                null);
        StructuredOutputMode structuredOutputMode = resolveStructuredOutputMode(securityDecisionRequest);
        // W3-9: a Layer2 second pass keeps the first prompt and adds only the facts it gathered.
        SecurityDecisionPromptSections.SecondPass secondPass = SecurityDecisionPromptSections.SecondPass.of(
                securityDecisionRequest.getParameter("layer2FirstPassUserPrompt", String.class),
                securityDecisionRequest.getParameter("layer2FirstPassVerdict", String.class),
                securityDecisionRequest.getParameter("layer2FirstPassPastRecordsState", String.class));
        // W3-7: the prompt budget is counted for the model the request names, as the reported budget is.
        StructuredPrompt structuredPrompt = promptSections.buildStructuredPrompt(
                context.getSecurityEvent(),
                context.getSessionContext(),
                context.getBehaviorAnalysis(),
                context.getRelatedDocuments(),
                budgetProfile,
                structuredOutputMode,
                estimationModelHint(securityDecisionRequest),
                secondPass
        );
        request.withParameter(STRUCTURED_PROMPT_CACHE_KEY, structuredPrompt);
        return structuredPrompt;
    }

    private StructuredOutputMode resolveStructuredOutputMode(AIRequest<? extends DomainContext> request) {
        if (request == null) {
            return StructuredOutputMode.VALIDATED_CONVERTER;
        }
        return StructuredOutputMode.fromValue(
                request.getParameter("structuredOutputMode", Object.class),
                StructuredOutputMode.VALIDATED_CONVERTER);
    }

    /**
     * The model the prompt is estimated for: the one the request names, else the one the analysis runs on (W4-7: a
     * security decision names none, and the measured calibration is kept per model).
     */
    private static String estimationModelHint(AIRequest<? extends DomainContext> request) {
        String requested = PromptGovernanceSupport.resolveRequestedModelHint(request);
        if (requested != null) {
            return requested;
        }
        String analysisModel = request != null ? request.getParameter("promptEstimationModelHint", String.class) : null;
        return analysisModel != null && !analysisModel.isBlank() ? analysisModel.trim() : null;
    }

    public record StructuredPrompt(
            String systemText,
            String userText,
            PromptExecutionMetadata executionMetadata) {

        public StructuredPrompt(String systemText, String userText) {
            this(systemText, userText, null);
        }
    }

    public static class DetectedPatterns {
        public final Set<String> osSet = new HashSet<>();
        public final Set<String> ipSet = new HashSet<>();
        public final Set<String> hourSet = new HashSet<>();
        public final Set<String> daySet = new HashSet<>();
        public final Set<String> uaSet = new HashSet<>();
        public final Set<String> pathSet = new HashSet<>();
        public String relatedContext;
        public boolean hasRelatedDocs;
    }

    @Getter
    @Setter
    public static class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private List<String> recentActions = List.of();
        private Integer sessionAgeMinutes;
        private Integer requestCount;

        public List<String> getRecentActions() {
            return recentActions != null ? recentActions : List.of();
        }
    }

    @Setter
    public static class BehaviorAnalysis {
        private boolean baselineEstablished;
        private List<ThreatIntelligenceSnapshot.ThreatSignalItem> activeThreatSignals = List.of();
        private ThreatIntelligenceMatchContext threatIntelligenceMatchContext;
        private ThreatKnowledgePackSnapshot threatKnowledgePack;
        private ThreatKnowledgePackMatchContext threatKnowledgePackMatchContext;
        private DetectionStrategyPackSnapshot detectionStrategyPack;
        private DetectionStrategyRuntimePack detectionStrategyRuntimePack;
        private Boolean isNewSession;
        private Boolean isNewDevice;
        private String previousUserAgentOS;
        private String currentUserAgentOS;
        private String[] baselineIpRanges;
        private String[] baselineOperatingSystems;
        private String[] baselineUserAgents;
        private String[] baselineFrequentPaths;
        private Integer[] baselineAccessHours;
        private Integer[] baselineAccessDays;
        private String[] baselineBrowsers;
        private String[] baselineDevices;
        private String[] baselineIpBands;
        private String[] baselineAuthenticationTypes;
        private String[] baselineActionFamilies;
        private String[] baselineResourceFamilies;
        private Long baselineUpdateCount;
        private Double baselineAvgTrustScore;
        private String previousUserAgentBrowser;
        private String currentUserAgentBrowser;
        private Long lastRequestIntervalMs;
        private String previousPath;
        /** The session's first device and this request's when they differ, "first -> current" (W2-14). */
        private String sessionDeviceChange;
        /** The session's first network and this request's when they differ, "first -> current" (W2-14). */
        private String sessionNetworkChange;
        private Double baselineAvgRequestRate;
        private boolean personalBaselineAvailable;
        private boolean personalBaselineEstablished;
        private boolean organizationBaselineAvailable;
        private boolean organizationBaselineEstablished;
        private boolean cohortSeedRecommended;
        private boolean cohortSeedApplied;
        private List<String> cohortSeedSupportingDimensions = List.of();
        private BaselineSeedSnapshot cohortBaselineSeed;
        private double cohortSeedWeight;
        private String cohortSeedWeightState;
        private List<String> cohortSeedPolicyFacts = List.of();
        private BaselineEvidenceSnapshot personalBaselineEvidence;
        private BaselineEvidenceSnapshot supportingBaselineEvidence;
        private LearningContextEvidence learningContextEvidence;

        public boolean isBaselineEstablished() {
            return baselineEstablished;
        }

        public List<ThreatIntelligenceSnapshot.ThreatSignalItem> getActiveThreatSignals() {
            return activeThreatSignals != null ? activeThreatSignals : List.of();
        }

        public ThreatIntelligenceMatchContext getThreatIntelligenceMatchContext() {
            return threatIntelligenceMatchContext;
        }

        public ThreatKnowledgePackSnapshot getThreatKnowledgePack() {
            return threatKnowledgePack;
        }

        public ThreatKnowledgePackMatchContext getThreatKnowledgePackMatchContext() {
            return threatKnowledgePackMatchContext;
        }

        public DetectionStrategyPackSnapshot getDetectionStrategyPack() {
            return detectionStrategyPack;
        }

        public DetectionStrategyRuntimePack getDetectionStrategyRuntimePack() {
            return detectionStrategyRuntimePack;
        }

        public Boolean getIsNewSession() {
            return isNewSession;
        }

        public Boolean getIsNewDevice() {
            return isNewDevice;
        }

        public String getPreviousUserAgentOS() {
            return previousUserAgentOS;
        }

        public String getCurrentUserAgentOS() {
            return currentUserAgentOS;
        }

        public String[] getBaselineIpRanges() {
            return baselineIpRanges;
        }

        public String[] getBaselineOperatingSystems() {
            return baselineOperatingSystems;
        }

        public String[] getBaselineUserAgents() {
            return baselineUserAgents;
        }

        public String[] getBaselineFrequentPaths() {
            return baselineFrequentPaths;
        }

        public Integer[] getBaselineAccessHours() {
            return baselineAccessHours;
        }

        public Integer[] getBaselineAccessDays() {
            return baselineAccessDays;
        }

        public String[] getBaselineBrowsers() {
            return baselineBrowsers;
        }

        public String[] getBaselineDevices() {
            return baselineDevices;
        }

        public String[] getBaselineIpBands() {
            return baselineIpBands;
        }

        public String[] getBaselineAuthenticationTypes() {
            return baselineAuthenticationTypes;
        }

        public String[] getBaselineActionFamilies() {
            return baselineActionFamilies;
        }

        public String[] getBaselineResourceFamilies() {
            return baselineResourceFamilies;
        }

        public Long getBaselineUpdateCount() {
            return baselineUpdateCount;
        }

        public Double getBaselineAvgTrustScore() {
            return baselineAvgTrustScore;
        }

        public String getPreviousUserAgentBrowser() {
            return previousUserAgentBrowser;
        }

        public String getCurrentUserAgentBrowser() {
            return currentUserAgentBrowser;
        }

        public Long getLastRequestIntervalMs() {
            return lastRequestIntervalMs;
        }

        public String getPreviousPath() {
            return previousPath;
        }

        public String getSessionDeviceChange() {
            return sessionDeviceChange;
        }

        public String getSessionNetworkChange() {
            return sessionNetworkChange;
        }

        public Double getBaselineAvgRequestRate() {
            return baselineAvgRequestRate;
        }

        public boolean isPersonalBaselineAvailable() {
            return personalBaselineAvailable;
        }

        public boolean isPersonalBaselineEstablished() {
            return personalBaselineEstablished;
        }

        public boolean isOrganizationBaselineAvailable() {
            return organizationBaselineAvailable;
        }

        public boolean isOrganizationBaselineEstablished() {
            return organizationBaselineEstablished;
        }

        public boolean isCohortSeedRecommended() {
            return cohortSeedRecommended;
        }

        public boolean isCohortSeedApplied() {
            return cohortSeedApplied;
        }

        public List<String> getCohortSeedSupportingDimensions() {
            return cohortSeedSupportingDimensions != null ? cohortSeedSupportingDimensions : List.of();
        }

        public BaselineSeedSnapshot getCohortBaselineSeed() {
            return cohortBaselineSeed;
        }

        public double getCohortSeedWeight() {
            return cohortSeedWeight;
        }

        public String getCohortSeedWeightState() {
            return cohortSeedWeightState;
        }

        public List<String> getCohortSeedPolicyFacts() {
            return cohortSeedPolicyFacts != null ? cohortSeedPolicyFacts : List.of();
        }

        public BaselineEvidenceSnapshot getPersonalBaselineEvidence() {
            return personalBaselineEvidence;
        }

        public BaselineEvidenceSnapshot getSupportingBaselineEvidence() {
            return supportingBaselineEvidence;
        }

        public LearningContextEvidence getLearningContextEvidence() {
            return learningContextEvidence;
        }
    }

    /** W6-9 (P6-CHANGE-6): the registry resolution context of a request, for the shadow run's candidate. */
    public PromptGovernanceResolutionContext resolutionContextOf(SecurityEvent event) {
        return promptSections.promptGovernanceResolutionContext(event);
    }
}
