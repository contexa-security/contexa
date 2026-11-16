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

import io.contexa.contexacommon.cache.ContexaCaffeine;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacommon.domain.TruthValues;
import io.contexa.contexacommon.domain.EventTimeZone;
import com.github.benmanes.caffeine.cache.Cache;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFactsResolver;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.context.policy.CanonicalContextFieldPolicy;
import io.contexa.contexacore.autonomous.context.policy.ContextEvidenceGuidance;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptBudgetTrim;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryLine;
import io.contexa.contexacore.autonomous.context.prompt.PromptEntryValues;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlot;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryRenderer;
import io.contexa.contexacore.autonomous.context.prompt.PromptMissingNotation;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryRendering;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionarySlotPlanProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptListItem;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRule;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleApplication;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleApplicationResult;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleApplier;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleProvider;
import io.contexa.contexacore.autonomous.context.snapshot.CurrentRequestSnapshot;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;
import io.contexa.contexacore.autonomous.context.support.PastRecordRelevance;
import io.contexa.contexacore.autonomous.context.support.PastRecordPostProcessor;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.CurrentVsObservedDeltaSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidenceAssembler;
import io.contexa.contexacore.autonomous.learning.evidence.ObservedPatternSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.RetrievedBehaviorEvidence;
import io.contexa.contexacore.autonomous.saas.dto.*;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyRuntimePack;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate.BehaviorAnalysis;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate.DetectedPatterns;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate.SessionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate.StructuredPrompt;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.AbstractStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptCompressionLedger;
import io.contexa.contexacore.std.components.prompt.PromptDuplicationRecord;
import io.contexa.contexacore.std.components.prompt.PromptEvidenceCompleteness;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolution;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolver;
import io.contexa.contexacore.std.components.prompt.bundle.ConfiguredPromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.PromptOmissionRecord;
import io.contexa.contexacore.std.components.prompt.PromptOmissionType;
import io.contexa.contexacore.std.components.prompt.PromptSectionPriorityClass;
import io.contexa.contexacore.std.components.prompt.PromptSemanticRisk;
import io.contexa.contexacore.std.components.prompt.PromptTokenEstimate;
import io.contexa.contexacore.std.components.prompt.PromptTokenEstimator;
import io.contexa.contexacore.std.components.prompt.PromptTokenEstimatorRegistry;
import io.contexa.contexacore.std.components.prompt.SecurityPromptSectionCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocument;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.BiPredicate;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;


/**
 * Builds security analysis prompts for Zero Trust AI evaluation.
 * <p>
 * Constructs structured prompts with sections for event data, behavioral patterns,
 * network context, and decision instructions. Each section is built by a dedicated
 * method for maintainability and clarity.
 * </p>
 */
@Slf4j
public class SecurityDecisionPromptSections {

    private static final List<PromptDuplicationRecord> DUPLICATION_INVENTORY = List.of(
            new PromptDuplicationRecord(
                    "request",
                    SecurityPromptSectionCatalog.CURRENT_REQUEST_AND_EVENT,
                    List.of(SecurityPromptSectionCatalog.BRIDGE_AND_COVERAGE, SecurityPromptSectionCatalog.RESOURCE_AND_ACTION),
                    "SecurityEventUserSectionBuilder",
                    "Retain only the current-request anchor facts here; bridge and resource sections own their semantic evidence."),
            new PromptDuplicationRecord(
                    "session",
                    SecurityPromptSectionCatalog.SESSION_NARRATIVE,
                    List.of(SecurityPromptSectionCatalog.CURRENT_REQUEST_AND_EVENT, SecurityPromptSectionCatalog.FRICTION_AND_APPROVAL),
                    PromptContextComposer.PRODUCER_SESSION_SECTION,
                    "Keep timeline and sequence facts in compact session form; remove repeated request recap and approval prose."),
            new PromptDuplicationRecord(
                    "device",
                    SecurityPromptSectionCatalog.DEVICE_CONTEXT,
                    List.of(SecurityPromptSectionCatalog.CURRENT_REQUEST_AND_EVENT),
                    PromptContextComposer.PRODUCER_DEVICE_SECTION,
                    "Device evidence must appear only in the device section; current request keeps only the event anchor."),
            new PromptDuplicationRecord(
                    "location",
                    SecurityPromptSectionCatalog.LOCATION_CONTEXT,
                    List.of(SecurityPromptSectionCatalog.CURRENT_REQUEST_AND_EVENT),
                    PromptContextComposer.PRODUCER_LOCATION_SECTION,
                    "Location evidence must appear only in the location section; current request keeps only the event anchor."),
            new PromptDuplicationRecord(
                    "resource",
                    SecurityPromptSectionCatalog.RESOURCE_AND_ACTION,
                    List.of(SecurityPromptSectionCatalog.CURRENT_REQUEST_AND_EVENT, SecurityPromptSectionCatalog.ROLE_SCOPE),
                    PromptContextComposer.PRODUCER_RESOURCE_SECTION,
                    "Resource semantics own sensitivity and requested action; scope sections keep only expected-vs-current comparisons."),
            new PromptDuplicationRecord(
                    "scope",
                    SecurityPromptSectionCatalog.ROLE_SCOPE,
                    List.of(SecurityPromptSectionCatalog.IDENTITY_AND_ROLE, SecurityPromptSectionCatalog.OBSERVED_AND_PERSONAL_WORK_PATTERN),
                    PromptContextComposer.PRODUCER_ROLE_SCOPE_SECTION,
                    "Role scope owns expected/fobidden families; identity keeps authorities and work pattern keeps observed behavior only."),
            new PromptDuplicationRecord(
                    "threat",
                    SecurityPromptSectionCatalog.THREAT_LEARNING_AND_MEMORY,
                    List.of(SecurityPromptSectionCatalog.CURRENT_REQUEST_AND_EVENT),
                    PromptContextComposer.PRODUCER_THREAT_SECTION,
                    "Threat memory owns comparable cases and campaign memory; current request keeps only live request facts.")
    );

    /** The threat section lines that hold the outside feed's own words (W3-6). */
    private static final List<String> OUTSIDE_TEXT_LABELS = List.of("SignalSummary", "CampaignSummary", "XaiSummary");

    /** Fact values stay whole while the prompt is built: the dictionary forbids cutting them (W3-7). */
    private static final boolean FACT_VALUES_STAY_WHOLE = factValuesStayWhole(SecurityDecisionPromptDictionary.ENTRIES);

    private final SecurityEventEnricher eventEnricher;
    private final TieredStrategyProperties tieredStrategyProperties;
    private final CanonicalSecurityContextProvider canonicalSecurityContextProvider;
    private final PromptContextComposer promptContextComposer;
    /** The default bundle's descriptor, for what every bundle shares: the prompt key and the template key. */
    private final PromptGovernanceDescriptor defaultDescriptor;
    private final PromptBundleSelector promptBundleSelector;
    /** Version names a selector chose or an event names that the store cannot find, each reported once. */
    private final Set<String> reportedUnfoundVersions = ConcurrentHashMap.newKeySet();
    private final PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver;
    private final PromptRuntimeGovernanceRuleProvider promptRuntimeGovernanceRuleProvider;
    private final PromptRuntimeGovernanceRuleApplier promptRuntimeGovernanceRuleApplier;
    private final LearningContextEvidenceAssembler learningContextEvidenceAssembler;
    private final Cache<String, byte[]> canonicalSecurityContextCache;
    /** The canonical contexts a replay fixed for its event, by event id (the replay's own id). */
    private final Cache<String, byte[]> pinnedCanonicalContexts = ContexaCaffeine.newBuilder()
            .maximumSize(256)
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .build();
    private final ObjectMapper canonicalContextSnapshotMapper;
    private final Cache<String, RenderedPromptSections> systemSectionsCache;
    private volatile MinimumActionRules.Settings minimumActionSettings = MinimumActionRules.Settings.DEFAULTS;
    /** Whether the host enforces the minimum action floors (OBSERVE or ENFORCE, K32). */
    private volatile String minimumActionMode = "OBSERVE";
    /** Where the version an event names is found (plan 6-2; the versions of a store from plan 6-3). */
    private volatile PromptVersionStore promptVersionStore = SecurityDecisionPromptDocument.productStore();
    /** The v1.0 dictionary: its slot plans and its renderer, with the v21 block titles. */
    private final PromptDictionarySlotPlanProvider v1DictionarySlotPlans =
            SecurityDecisionPromptDictionary.v1SlotPlanProvider();
    private final PromptDictionaryRenderer v1DictionaryRenderer = new PromptDictionaryRenderer(
            SecurityDecisionPromptDictionary.V1_ENTRIES, v1DictionarySlotPlans,
            SecurityDecisionPromptDocument.blockTitles(SecurityDecisionPromptDocument.product()));
    /** The v1.0 dictionary of a bundle with the decision rules: the v1.0 entries and the conclusions the rules read. */
    private final PromptDictionarySlotPlanProvider v1RulesDictionarySlotPlans =
            SecurityDecisionPromptDictionary.v1RulesSlotPlanProvider();
    private final PromptDictionaryRenderer v1RulesDictionaryRenderer = new PromptDictionaryRenderer(
            SecurityDecisionPromptDictionary.V1_RULES_ENTRIES, v1RulesDictionarySlotPlans,
            SecurityDecisionPromptDocument.blockTitles(SecurityDecisionPromptDocument.product()));

    /** The user prompt layout a v20 render states in its execution metadata (W3-2). */
    /** The v20 user prompt layout: the dictionary blocks (R1b-3: the one name the render, Layer2 and the inspector use). */
    public static final String USER_PROMPT_LAYOUT_V20 = "v20-dictionary-blocks";
    /** The v21 user prompt layout: the v21 dictionary blocks (records and comparisons, no conclusions). */
    public static final String USER_PROMPT_LAYOUT_V21 = "v21-dictionary-blocks";
    /** The v1.0 user prompt layout: the v1.0 dictionary blocks (the v21 records and the facts v1.0 adds). */
    public static final String USER_PROMPT_LAYOUT_V1 = "v1.0-dictionary-blocks";
    /**
     * The event metadata of the version a decision runs (plan 3.4), fixed when the decision starts: its name
     * ({@code v2.0}; the release of the product document when no version was chosen), what chose it and its content
     * hash. Every later prompt of the decision, a Layer2 prompt, a second pass, a correction or a judgement again, is
     * drawn with that version, wherever the label moved meanwhile.
     */
    public static final String EVENT_BUNDLE_VERSION = "promptBundleSelection.version";
    public static final String EVENT_BUNDLE_SOURCE = "promptBundleSelection.source";
    public static final String EVENT_BUNDLE_CONTENT_HASH = "promptBundleSelection.contentHash";
    private static final String SECOND_PASS_LAYOUT = "v20-second-pass";
    /** PR-91: the canonical contexts kept may take a thirty-second of the maximum heap, within these bounds. */
    private static final int CANONICAL_CONTEXT_HEAP_SHARE_DIVISOR = 32;
    private static final long MIN_CANONICAL_CONTEXT_BYTES = 8L * 1024 * 1024;
    private static final long MAX_CANONICAL_CONTEXT_BYTES = 128L * 1024 * 1024;
    private static final String PROMPT_CACHE_KEY_PREFIX = "contexa-";
    /** The event metadata that says whether past records reached the user prompt the model gets (BR-C8, QF-16). */
    static final String RAG_PROJECTED_TO_FINAL_PROMPT = "ragProjectedToFinalPrompt";
    /**
     * A past record line of a dictionary prompt: a PAST RECORDS line, a SECOND PASS line of a new record, or a similar
     * case line of a v1.0 bundle with the similarity search (A13).
     */
    private static final Pattern DICTIONARY_PAST_RECORD_LABEL = Pattern.compile("(New)?PastRecord\\d+|SimilarCase\\d+");
    public SecurityDecisionPromptSections(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer) {
        this(eventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                null,
                null,
                null);
    }

    /**
     * @param promptBundleSelector chooses the version each decision runs (plan 3.4, the version resolver of the
     *                             console); null for the name the configuration gives
     *                             ({@code contexa.security.tiered.prompt-bundle.active}), found in the version store
     */
    public SecurityDecisionPromptSections(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer,
            PromptBundleSelector promptBundleSelector,
            PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver,
            PromptRuntimeGovernanceRuleProvider promptRuntimeGovernanceRuleProvider) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.tieredStrategyProperties = tieredStrategyProperties != null ? tieredStrategyProperties : new TieredStrategyProperties();
        this.canonicalSecurityContextProvider = canonicalSecurityContextProvider;
        this.promptContextComposer = promptContextComposer;
        this.defaultDescriptor = SecurityDecisionPromptBundles.DEFAULT.descriptor();
        this.promptBundleSelector = promptBundleSelector != null
                ? promptBundleSelector
                : new ConfiguredPromptBundleSelector(this.tieredStrategyProperties.getPromptBundle().getActive());
        this.promptGovernanceDescriptorResolver = promptGovernanceDescriptorResolver != null
                ? promptGovernanceDescriptorResolver
                : PromptGovernanceDescriptorResolver.identity();
        this.promptRuntimeGovernanceRuleProvider = promptRuntimeGovernanceRuleProvider != null
                ? promptRuntimeGovernanceRuleProvider
                : PromptRuntimeGovernanceRuleProvider.none();
        this.promptRuntimeGovernanceRuleApplier = new PromptRuntimeGovernanceRuleApplier();
        this.learningContextEvidenceAssembler = new LearningContextEvidenceAssembler();
        this.canonicalContextSnapshotMapper = new ObjectMapper().findAndRegisterModules();
        // PR-91: its bytes, not its entries, are what a small heap has room for: a context takes tens of kilobytes.
        this.canonicalSecurityContextCache = ContexaCaffeine.newBuilder()
                .maximumWeight(defaultCanonicalContextBudgetBytes(Runtime.getRuntime().maxMemory()))
                .weigher((String key, byte[] snapshot) -> snapshot.length + 2 * key.length())
                .expireAfterWrite(15, TimeUnit.MINUTES)
                .build();
        this.systemSectionsCache = ContexaCaffeine.newBuilder()
                .maximumSize(64)
                .expireAfterAccess(30, TimeUnit.MINUTES)
                .build();
    }

    public SecurityDecisionPromptSections(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties) {
        this(eventEnricher, tieredStrategyProperties, null, null);
    }

    /**
     * Builds a structured prompt with system/user separation for KV cache optimization.
     * The system text (instructions + decision format) is fixed across requests,
     * allowing Ollama to reuse its KV cache prefix.
     *
     * @param event the security event to analyze
     * @param sessionContext the current session context
     * @param behaviorAnalysis the behavioral analysis data
     * @param relatedDocuments the RAG-retrieved related documents
     * @return structured prompt with separated system and user text
     */
    public StructuredPrompt buildStructuredPrompt(SecurityEvent event,
                                                   SessionContext sessionContext,
                                                   BehaviorAnalysis behaviorAnalysis,
                                                   List<Document> relatedDocuments) {
        return buildStructuredPrompt(
                event,
                sessionContext,
                behaviorAnalysis,
                relatedDocuments,
                resolveBudgetProfile(event, behaviorAnalysis),
                StructuredOutputMode.VALIDATED_CONVERTER
        );
    }

    public StructuredPrompt buildStructuredPrompt(SecurityEvent event,
                                                  SessionContext sessionContext,
                                                  BehaviorAnalysis behaviorAnalysis,
                                                  List<Document> relatedDocuments,
                                                  PromptBudgetProfile budgetProfile) {
        return buildStructuredPrompt(
                event,
                sessionContext,
                behaviorAnalysis,
                relatedDocuments,
                budgetProfile,
                StructuredOutputMode.VALIDATED_CONVERTER
        );
    }

    public StructuredPrompt buildStructuredPrompt(SecurityEvent event,
                                                  SessionContext sessionContext,
                                                  BehaviorAnalysis behaviorAnalysis,
                                                  List<Document> relatedDocuments,
                                                   PromptBudgetProfile budgetProfile,
                                                   StructuredOutputMode structuredOutputMode) {
        return buildStructuredPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments, budgetProfile,
                structuredOutputMode, null);
    }

    /** As above, with the request's model hint the prompt budget is counted for (W3-7). */
    public StructuredPrompt buildStructuredPrompt(SecurityEvent event,
                                                  SessionContext sessionContext,
                                                  BehaviorAnalysis behaviorAnalysis,
                                                  List<Document> relatedDocuments,
                                                  PromptBudgetProfile budgetProfile,
                                                  StructuredOutputMode structuredOutputMode,
                                                  String modelHint) {
        return buildStructuredPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments, budgetProfile,
                structuredOutputMode, modelHint, null);
    }

    /** As above, for a Layer2 second pass that adds to the first prompt (W3-9); null for any other prompt. */
    public StructuredPrompt buildStructuredPrompt(SecurityEvent event,
                                                  SessionContext sessionContext,
                                                  BehaviorAnalysis behaviorAnalysis,
                                                  List<Document> relatedDocuments,
                                                  PromptBudgetProfile budgetProfile,
                                                  StructuredOutputMode structuredOutputMode,
                                                  String modelHint,
                                                  SecondPass secondPass) {

        long promptBuildStartedNanos = System.nanoTime();
        PromptBudgetProfile effectiveBudgetProfile = budgetProfile != null
                ? budgetProfile
                : resolveBudgetProfile(event, behaviorAnalysis);
        long createContextStartedNanos = System.nanoTime();
        SecurityPromptBuildContext buildContext;
        try (PromptTemplateUtils.TruncationScope ignored =
                     PromptTemplateUtils.disableTruncationForCurrentThread(FACT_VALUES_STAY_WHOLE)) {
            buildContext = createBuildContext(
                    event,
                    sessionContext,
                    behaviorAnalysis,
                    relatedDocuments,
                    effectiveBudgetProfile,
                    structuredOutputMode
            );
        }
        long createBuildContextMicros = elapsedMicros(createContextStartedNanos);
        long descriptorStartedNanos = System.nanoTime();
        PromptGovernanceResolutionContext runtimeResolutionContext = promptGovernanceResolutionContext(buildContext);
        SelectedBundle selected = selectBundle(buildContext != null ? buildContext.getEvent() : null,
                runtimeResolutionContext);
        DictionaryKit kit = dictionaryKit(selected.version());
        if (buildContext != null && buildContext.getCanonicalSecurityContext() != null) {
            // The decision rules, the response check and the minimum action record read the core's conclusions; they
            // stay in memory beside the records, which the sealed context keeps.
            CanonicalSecurityContext canonical = buildContext.getCanonicalSecurityContext();
            canonical.setConclusionFacts(canonical.getDecisionFacts());
        }
        // V-4: the prompt states the decision facts as records and comparisons; the sealed context keeps them.
        restateDecisionFactsAsRecords(buildContext);
        PromptGovernanceDescriptorResolution governanceResolution =
                resolvePromptGovernanceDescriptor(selected.bundle().descriptor(), runtimeResolutionContext);
        long governanceDescriptorMicros = elapsedMicros(descriptorStartedNanos);
        long runtimeGovernanceStartedNanos = System.nanoTime();
        PromptRuntimeGovernanceRuleContext runtimeGovernanceRuleContext =
                promptRuntimeGovernanceRuleContext(runtimeResolutionContext, governanceResolution.descriptor());
        List<PromptRuntimeGovernanceRule> runtimeGovernanceRules =
                promptRuntimeGovernanceRuleProvider.activeRules(runtimeGovernanceRuleContext);
        buildContext = buildContext.withRuntimeGovernanceRules(runtimeGovernanceRules);
        long runtimeGovernanceLookupMicros = elapsedMicros(runtimeGovernanceStartedNanos);

        long renderStartedNanos = System.nanoTime();
        long systemRenderMicros;
        long userRenderMicros;
        RenderedPromptSections systemSections;
        RenderedPromptSections userSections;
        CachedRenderedPromptSections cachedSystemSections;
        try (PromptTemplateUtils.TruncationScope ignored =
                     PromptTemplateUtils.disableTruncationForCurrentThread(FACT_VALUES_STAY_WHOLE)) {
            long systemRenderStartedNanos = System.nanoTime();
            cachedSystemSections = composeSystemSections(buildContext, effectiveBudgetProfile, selected.bundle());
            systemRenderMicros = elapsedMicros(systemRenderStartedNanos);
            systemSections = cachedSystemSections.sections();
            long userRenderStartedNanos = System.nanoTime();
            userSections = secondPass != null
                    ? composeSecondPass(buildContext, secondPass, kit)
                    : composeDictionaryBlocks(buildContext,
                    modelSystemPrompt(systemSections.composedText(), structuredOutputMode), effectiveBudgetProfile,
                    modelHint, kit);
            userRenderMicros = elapsedMicros(userRenderStartedNanos);
        }
        List<String> sectionSet = mergeSectionKeys(systemSections.renderedSectionKeys(), userSections.renderedSectionKeys());
        List<PromptOmissionRecord> omissionLedger = userSections.omissionLedger();
        List<String> omittedSections = omissionLedger.stream()
                .map(PromptOmissionRecord::sectionKey)
                .distinct()
                .toList();
        String systemText = systemSections.composedText();
        String userText = userSections.composedText();
        long runtimeGovernanceApplyStartedNanos = System.nanoTime();
        // Plan 2.3 A10: a rule written for a label of the earlier section prompt is moved to the dictionary slot its
        // label went to, so it reaches the line of that fact.
        List<PromptRuntimeGovernanceRule> dictionaryRules = SectionRuleSlots.moved(runtimeGovernanceRules, kit.slotPlans(),
                kit.entries(), promptContextComposer);
        PromptRuntimeGovernanceRuleApplicationResult runtimeGovernanceResult =
                promptRuntimeGovernanceRuleApplier.applyToDictionaryPrompt(userText, dictionaryRules, kit.slotPlans());
        userText = runtimeGovernanceResult.userPrompt();
        if (secondPass != null) {
            // The first prompt went through the rule appliers in the first pass; it is put back as it was.
            userText = userText.isBlank() ? secondPass.firstUserPrompt().stripTrailing()
                    : secondPass.firstUserPrompt().stripTrailing() + "\n\n" + userText;
        }
        long runtimeGovernanceApplyMicros = elapsedMicros(runtimeGovernanceApplyStartedNanos);
        long renderTimeMs = elapsedMillis(renderStartedNanos);
        long renderTotalMicros = elapsedMicros(renderStartedNanos);
        // BR-C8 (QF-16): whether past records reached the prompt is read from the prompt the model gets, after the list
        // cap, the budget, the runtime rules and a second pass's first prompt; the retrieval only knew they were allowed.
        markPastRecordProjection(event, drawsPastRecords(userText));
        long auditStartedNanos = System.nanoTime();
        // Plan 2.3 A11: the render audits its system text and its own dictionary form.
        SecurityPromptContractAudit promptContractAudit = withDictionaryFormViolations(
                SecurityPromptContractVerifier.audit(systemText, buildContext), userText, kit.entries());
        long promptContractAuditMicros = elapsedMicros(auditStartedNanos);
        long completenessStartedNanos = System.nanoTime();
        PromptEvidenceCompleteness promptEvidenceCompleteness = evaluateCompleteness(buildContext, omissionLedger,
                promptContractAudit, userSections.metadata().get(PROMPT_EVIDENCE_COMPLETENESS_REASONS) instanceof List<?> facts
                        ? facts : null, true);
        long completenessMicros = elapsedMicros(completenessStartedNanos);
        long metadataStartedNanos = System.nanoTime();
        Map<String, Object> supplementalMetadata = new LinkedHashMap<>();
        supplementalMetadata.put("promptBundleSelectionSource", selected.source().name());
        // Plan 3.8 (9): the version the prompt was drawn with and its content hash, which the sealed package keeps.
        supplementalMetadata.put(PromptExecutionMetadata.PROMPT_VERSION_NAME, selected.versionName());
        supplementalMetadata.put(PromptExecutionMetadata.PROMPT_CONTENT_HASH, selected.version().contentHash());
        // The layout says which user prompt was drawn, next to the bundle that drew it.
        supplementalMetadata.put(PromptExecutionMetadata.USER_PROMPT_LAYOUT_VERSION, kit.layoutName());
        supplementalMetadata.putAll(userSections.metadata());
        supplementalMetadata.put("promptCacheKey", promptCacheKey(modelSystemPrompt(systemText, structuredOutputMode)));
        supplementalMetadata.putAll(buildRagPromptMetadata(buildContext));
        supplementalMetadata.putAll(buildLearningPromptMetadata(buildContext, sectionSet));
        supplementalMetadata.putAll(buildPromptContractMetadata(promptContractAudit));
        supplementalMetadata.putAll(governanceResolution.supplementalMetadata());
        supplementalMetadata.putAll(buildPqaPromptCacheMetadata(
                systemText,
                effectiveBudgetProfile,
                cachedSystemSections,
                userText,
                renderTimeMs));
        supplementalMetadata.putAll(buildPromptRuntimeGovernanceMetadata(runtimeGovernanceRules, runtimeGovernanceResult));
        supplementalMetadata.putAll(promptRuntimeGovernanceRuleProvider.runtimeCacheMetadata(runtimeGovernanceRuleContext));
        long metadataBuildMicros = elapsedMicros(metadataStartedNanos);
        long recordApplicationsStartedNanos = System.nanoTime();
        promptRuntimeGovernanceRuleProvider.recordApplications(
                runtimeGovernanceRuleContext,
                runtimeGovernanceResult.applications(),
                PromptGovernanceSupport.sha256(systemText != null ? systemText : ""),
                PromptGovernanceSupport.sha256(userText != null ? userText : ""));
        supplementalMetadata.putAll(
                promptRuntimeGovernanceRuleProvider.runtimeCacheMetadata(runtimeGovernanceRuleContext));
        long recordApplicationsMicros = elapsedMicros(recordApplicationsStartedNanos);
        supplementalMetadata.put("promptTiming.createBuildContextMicros", createBuildContextMicros);
        supplementalMetadata.put("promptTiming.runtimeGovernanceLookupMicros", runtimeGovernanceLookupMicros);
        supplementalMetadata.put("promptTiming.systemRenderMicros", systemRenderMicros);
        supplementalMetadata.put("promptTiming.userRenderMicros", userRenderMicros);
        supplementalMetadata.put("promptTiming.renderTotalMicros", renderTotalMicros);
        supplementalMetadata.put("promptTiming.runtimeGovernanceApplyMicros", runtimeGovernanceApplyMicros);
        supplementalMetadata.put("promptTiming.contractAuditMicros", promptContractAuditMicros);
        supplementalMetadata.put("promptTiming.completenessMicros", completenessMicros);
        supplementalMetadata.put("promptTiming.governanceDescriptorMicros", governanceDescriptorMicros);
        supplementalMetadata.put("promptTiming.metadataBuildMicros", metadataBuildMicros);
        supplementalMetadata.put("promptTiming.recordApplicationsMicros", recordApplicationsMicros);
        supplementalMetadata.put("promptTiming.totalStructuredPromptBuildMicros", elapsedMicros(promptBuildStartedNanos));
        putSectionTimingMetadata(supplementalMetadata, "promptTiming.systemSection.", systemSections.sectionTimings());
        putSectionTimingMetadata(supplementalMetadata, "promptTiming.userSection.", userSections.sectionTimings());

        return new StructuredPrompt(
                systemText,
                userText,
                PromptGovernanceSupport.buildExecutionMetadata(
                        governanceResolution.descriptor(),
                        effectiveBudgetProfile,
                        sectionSet,
                        omittedSections,
                        omissionLedger,
                        DUPLICATION_INVENTORY,
                        promptEvidenceCompleteness,
                        modelHint,
                        systemText,
                        userText,
                        systemText,
                        userText,
                        PromptCompressionLedger.identity(systemText, userText),
                        supplementalMetadata)
        );
    }

    /**
     * Builds the complete security analysis prompt as a single string.
     * Backward-compatible wrapper around buildStructuredPrompt().
     */
    public String buildPrompt(SecurityEvent event,
                              SessionContext sessionContext,
                              BehaviorAnalysis behaviorAnalysis,
                              List<Document> relatedDocuments) {

        StructuredPrompt structured = buildStructuredPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments);
        return structured.systemText() + structured.userText();
    }

    /** W4-7 (inventory 6 bundle 30): prompt timings in microseconds; whole milliseconds were mostly 0. */
    private long elapsedMicros(long startedNanos) {
        return Math.max(0L, TimeUnit.NANOSECONDS.toMicros(System.nanoTime() - startedNanos));
    }

    private long elapsedMillis(long startedNanos) {
        return Math.max(0L, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos));
    }

    private void putSectionTimingMetadata(Map<String, Object> metadata, String prefix, Map<String, Long> timings) {
        if (metadata == null || timings == null || timings.isEmpty()) {
            return;
        }
        timings.forEach((sectionKey, elapsedMicros) -> {
            if (sectionKey != null && elapsedMicros != null) {
                metadata.put(prefix + sectionKey + ".micros", elapsedMicros);
            }
        });
    }

    private PromptGovernanceDescriptorResolution resolvePromptGovernanceDescriptor(
            PromptGovernanceDescriptor bundleDescriptor,
            PromptGovernanceResolutionContext resolutionContext) {
        try {
            PromptGovernanceDescriptorResolution resolution =
                    promptGovernanceDescriptorResolver.resolve(bundleDescriptor, resolutionContext);
            return resolution != null
                    ? resolution
                    : PromptGovernanceDescriptorResolution.fallback(bundleDescriptor, resolutionContext);
        }
        catch (RuntimeException exception) {
            log.warn("Prompt governance descriptor resolution failed. Falling back to static descriptor.", exception);
            return PromptGovernanceDescriptorResolution.fallback(bundleDescriptor, resolutionContext);
        }
    }

    /**
     * The bundle the event runs, with its version fixed on the event when it is asked first (W3-18, plan 3.4): the
     * strategy asks before its past record search, since the version decides how the past records are read, and every
     * prompt of the decision keeps that version.
     */
    public SecurityDecisionPromptBundles.Bundle bundleOf(SecurityEvent event) {
        return selectBundle(event, promptGovernanceResolutionContext(event)).bundle();
    }

    /**
     * The version this prompt is drawn with (plan 3.4, 3.8). A later prompt of a decision is drawn with the version
     * fixed on its event. Otherwise the selector chooses and the choice is fixed on the event: its name, what chose it
     * and its content hash. A choice the store cannot find, or no choice, runs the product version, and a name the store
     * cannot find is reported as an error once (plan 3.8, 7).
     */
    private SelectedBundle selectBundle(SecurityEvent event, PromptGovernanceResolutionContext resolutionContext) {
        Optional<SelectedBundle> fixed = fixedOn(event);
        if (fixed.isPresent()) {
            return fixed.get();
        }
        SelectedBundle selected = runnable(choose(resolutionContext, subjectKey(event)));
        if (event != null) {
            event.addMetadata(EVENT_BUNDLE_VERSION, selected.versionName());
            event.addMetadata(EVENT_BUNDLE_SOURCE, selected.source().name());
            event.addMetadata(EVENT_BUNDLE_CONTENT_HASH, selected.version().contentHash());
        }
        return selected;
    }

    /**
     * The version fixed on the event when its decision started; empty before that. The content hash follows the version
     * the name finds, so a copy that names another version (a shadow run's) states that version's hash.
     */
    private Optional<SelectedBundle> fixedOn(SecurityEvent event) {
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        if (metadata == null) {
            return Optional.empty();
        }
        String name = metadataText(metadata.get(EVENT_BUNDLE_VERSION));
        PromptBundleSelectionSource source = selectionSource(metadata.get(EVENT_BUNDLE_SOURCE));
        if (name == null || source == null) {
            return Optional.empty();
        }
        Optional<AssembledPrompt> version = findVersion(name, source);
        if (version.isPresent() && !version.get().contentHash().equals(metadata.get(EVENT_BUNDLE_CONTENT_HASH))) {
            event.addMetadata(EVENT_BUNDLE_CONTENT_HASH, version.get().contentHash());
        }
        return Optional.of(new SelectedBundle(SecurityDecisionPromptBundles.DEFAULT, source, name,
                version.orElseGet(SecurityDecisionPromptDocument::product)));
    }

    private PromptBundleSelection choose(PromptGovernanceResolutionContext resolutionContext, String subjectKey) {
        try {
            PromptBundleSelection selection = promptBundleSelector.select(resolutionContext, subjectKey);
            return selection != null ? selection : PromptBundleSelection.none();
        }
        catch (RuntimeException exception) {
            log.error("Prompt version selection failed; the product version {} runs",
                    SecurityDecisionPromptDocument.product().release(), exception);
            return PromptBundleSelection.none();
        }
    }

    private SelectedBundle runnable(PromptBundleSelection selection) {
        AssembledPrompt product = SecurityDecisionPromptDocument.product();
        if (selection.bundleVersion() == null || selection.bundleVersion().isBlank()) {
            return new SelectedBundle(SecurityDecisionPromptBundles.DEFAULT, PromptBundleSelectionSource.BUILD_DEFAULT,
                    product.release(), product);
        }
        String name = selection.bundleVersion().trim();
        Optional<AssembledPrompt> version = findVersion(name, selection.source());
        if (version.isPresent()) {
            return new SelectedBundle(SecurityDecisionPromptBundles.DEFAULT, selection.source(), name, version.get());
        }
        return new SelectedBundle(SecurityDecisionPromptBundles.DEFAULT, PromptBundleSelectionSource.BUILD_DEFAULT,
                product.release(), product);
    }

    /** The version of the name in the store; empty, reported as an error once per name, when the store has none. */
    private Optional<AssembledPrompt> findVersion(String name, PromptBundleSelectionSource source) {
        Optional<AssembledPrompt> version;
        try {
            version = promptVersionStore.find(SecurityDecisionPromptDocument.PROMPT, name);
        }
        catch (RuntimeException exception) {
            version = Optional.empty();
        }
        if (version.isEmpty() && reportedUnfoundVersions.add(name)) {
            log.error("Prompt version {} chosen by {} cannot be found; the product version {} runs", name, source,
                    SecurityDecisionPromptDocument.product().release());
        }
        return version;
    }

    /** The requester a canary share is drawn by: the user, else the session, else the event. */
    private static String subjectKey(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        return StringUtils.hasText(event.getUserId()) ? event.getUserId()
                : StringUtils.hasText(event.getSessionId()) ? event.getSessionId()
                : event.getEventId();
    }

    private static String metadataText(Object value) {
        return value != null && StringUtils.hasText(String.valueOf(value)) ? String.valueOf(value).trim() : null;
    }

    private static PromptBundleSelectionSource selectionSource(Object value) {
        String text = metadataText(value);
        if (text == null) {
            return null;
        }
        for (PromptBundleSelectionSource source : PromptBundleSelectionSource.values()) {
            if (source.name().equals(text)) {
                return source;
            }
        }
        return null;
    }

    /** The bundle a prompt is drawn with, what chose its version, the version's name and the version. */
    private record SelectedBundle(SecurityDecisionPromptBundles.Bundle bundle, PromptBundleSelectionSource source,
                                  String versionName, AssembledPrompt version) {
    }

    private PromptGovernanceResolutionContext promptGovernanceResolutionContext(SecurityPromptBuildContext buildContext) {
        return promptGovernanceResolutionContext(buildContext != null ? buildContext.getEvent() : null);
    }

    /** The registry resolution context of a request, as the bundle selection reads it (W6-9 reads it too). */
    public PromptGovernanceResolutionContext promptGovernanceResolutionContext(SecurityEvent event) {
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        Map<String, Object> attributes = new LinkedHashMap<>();
        if (metadata != null) {
            metadata.forEach((key, value) -> {
                if (key != null && value != null) {
                    attributes.put(key, value);
                }
            });
        }
        return new PromptGovernanceResolutionContext(
                firstNonBlankText(metadataValue(metadata, "registryScope"),
                        metadataValue(metadata, "promptRegistryScope"),
                        metadataValue(metadata, "governanceRegistryScope"),
                        "PLATFORM_GLOBAL"),
                defaultDescriptor.promptKey(),
                defaultDescriptor.templateKey(),
                firstNonBlankText(metadataValue(metadata, "tenantId"), metadataValue(metadata, "tenant_id")),
                firstNonBlankText(metadataValue(metadata, "resourceId"),
                        metadataValue(metadata, "managedResourceId"),
                        metadataValue(metadata, "endpointKey")),
                firstNonBlankText(metadataValue(metadata, "protectableResourceUrl"),
                        metadataValue(metadata, "managedResourceUrl"),
                        metadataValue(metadata, "resourceUrlTemplate"),
                        metadataValue(metadata, "resourceUrl"),
                        extractRequestPath(event)),
                firstNonBlankText(metadataValue(metadata, "protectableHttpMethod"),
                        metadataValue(metadata, "managedHttpMethod"),
                        metadataValue(metadata, "httpMethod"),
                        metadataValue(metadata, "method")),
                attributes);
    }

    private Object metadataValue(Map<String, Object> metadata, String key) {
        return metadata == null ? null : metadata.get(key);
    }

    private boolean metadataBoolean(Map<String, Object> metadata, String key) {
        if (metadata == null || key == null) {
            return false;
        }
        Object value = metadata.get(key);
        if (value instanceof Boolean bool) {
            return bool;
        }
        return Boolean.TRUE.equals(TruthValues.parse(value));
    }

    private int metadataInt(Map<String, Object> metadata, String key, int fallback) {
        if (metadata == null || key == null) {
            return fallback;
        }
        Object value = metadata.get(key);
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Integer.parseInt(text.trim());
            }
            catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    private String ragRetrievalState(
            boolean searchExecuted,
            boolean unavailable,
            boolean timedOut,
            boolean permissionFiltered,
            int relatedDocumentCount) {
        if (timedOut) {
            return "TIMEOUT";
        }
        if (unavailable) {
            return "UNAVAILABLE";
        }
        if (!searchExecuted) {
            return "NOT_REQUESTED";
        }
        if (permissionFiltered && relatedDocumentCount == 0) {
            return "PERMISSION_FILTERED";
        }
        return relatedDocumentCount > 0 ? "AVAILABLE" : "ZERO_RESULTS";
    }

    private String ragAbsenceReason(
            boolean searchExecuted,
            boolean unavailable,
            boolean timedOut,
            boolean permissionFiltered,
            int relatedDocumentCount) {
        if (relatedDocumentCount > 0) {
            return null;
        }
        if (timedOut) {
            return "TIMEOUT";
        }
        if (unavailable) {
            return "UNAVAILABLE";
        }
        if (!searchExecuted) {
            return "NOT_REQUESTED";
        }
        return permissionFiltered ? "PERMISSION_FILTER_EXCLUDED" : "ZERO_RESULTS";
    }

    private String normalizeRagAbsenceReason(String absenceReason, boolean permissionFiltered, int relatedDocumentCount) {
        if (permissionFiltered && relatedDocumentCount == 0 && "PERMISSION_FILTERED".equalsIgnoreCase(absenceReason)) {
            return "PERMISSION_FILTER_EXCLUDED";
        }
        return absenceReason;
    }

    private String ragApplicability(boolean searchExecuted, String retrievalState, int relatedDocumentCount) {
        if (!searchExecuted) {
            return "NOT_EXECUTED";
        }
        if (relatedDocumentCount > 0) {
            return "DOCUMENTS_RETRIEVED";
        }
        if ("TIMEOUT".equalsIgnoreCase(retrievalState)
                || "UNAVAILABLE".equalsIgnoreCase(retrievalState)
                || "FAILED".equalsIgnoreCase(retrievalState)) {
            return "SEARCH_UNAVAILABLE";
        }
        return "ZERO_RESULTS_DECLARED";
    }

    /**
     * The past record retrieval state of the request, computed once and written to the event metadata, where the
     * sealed evidence and the post-processing read it. Both the v19 section and the v20 values read it (W3-2).
     */
    RagState ragState(SecurityPromptBuildContext context) {
        SecurityEvent event = context.getEvent();
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        List<Document> relatedDocuments = context.getRelatedDocuments() != null
                ? context.getRelatedDocuments()
                : List.of();
        int relatedDocumentCount = relatedDocuments.size();
        boolean unavailable = metadataBoolean(metadata, "ragUnavailable");
        boolean timedOut = metadataBoolean(metadata, "ragTimedOut");
        boolean permissionFiltered = metadataBoolean(metadata, "ragPermissionFiltered");
        boolean searchExecuted = metadataBoolean(metadata, "ragSearchExecuted")
                || relatedDocumentCount > 0
                || unavailable
                || timedOut
                || StringUtils.hasText(firstNonBlankText(
                metadataValue(metadata, "ragRetrievalState"),
                metadataValue(metadata, "retrievalStatus"),
                metadataValue(metadata, "status")));
        String retrievalState = firstNonBlankText(
                metadataValue(metadata, "ragRetrievalState"),
                metadataValue(metadata, "retrievalStatus"),
                metadataValue(metadata, "status"),
                ragRetrievalState(searchExecuted, unavailable, timedOut, permissionFiltered, relatedDocumentCount));
        String absenceReason = firstNonBlankText(
                metadataValue(metadata, "ragAbsenceReason"),
                metadataValue(metadata, "absenceReason"),
                ragAbsenceReason(searchExecuted, unavailable, timedOut, permissionFiltered, relatedDocumentCount));
        absenceReason = normalizeRagAbsenceReason(absenceReason, permissionFiltered, relatedDocumentCount);
        String projectionState = firstNonBlankText(
                metadataValue(metadata, "ragProjectionState"),
                relatedDocumentCount > 0
                        ? "PROJECTED"
                        : (permissionFiltered
                        ? "PERMISSION_FILTERED_DECLARED"
                        : ("ZERO_RESULTS".equalsIgnoreCase(retrievalState)
                        ? "ZERO_RESULTS_DECLARED"
                        : "NOT_APPLICABLE")));
        String applicability = ragApplicability(searchExecuted, retrievalState, relatedDocumentCount);
        String ragRelevance = ragRelevance(event, relatedDocuments);
        putRagMetadata(
                event,
                searchExecuted,
                retrievalState,
                absenceReason,
                projectionState,
                applicability,
                ragRelevance,
                relatedDocumentCount,
                permissionFiltered);
        return new RagState(searchExecuted, retrievalState, absenceReason, projectionState, applicability, ragRelevance,
                relatedDocumentCount, permissionFiltered,
                metadataInt(metadata, "ragCandidateDocumentCount", relatedDocumentCount),
                metadataInt(metadata, "ragAuthorizedDocumentCount", relatedDocumentCount),
                metadataInt(metadata, "ragDeniedDocumentCount", 0),
                firstNonBlankText(metadataValue(metadata, "ragEarlierRetrievalState")));
    }

    /**
     * The past records of the request for the v20 PAST RECORDS block: one line of the dictionary 7 form per set of
     * facts (W3-3), copies of one record counted once; the block orders them by the dictionary rule.
     */
    List<PromptListItem> pastRecordItems(SecurityPromptBuildContext context) {
        return pastRecordItems(context, null);
    }

    /** The past record lines with the target field the marker writes (A3-5: a v21 line), or the target itself. */
    List<PromptListItem> pastRecordItems(SecurityPromptBuildContext context, String targetMarker) {
        List<Document> relatedDocuments = context.getRelatedDocuments() != null
                ? context.getRelatedDocuments()
                : List.of();
        if (relatedDocuments.isEmpty()) {
            return List.of();
        }
        // BR-S4: the records reach the lines through the past record post-processing step (the same ranking).
        return PastRecordLines.items(
                PastRecordPostProcessor.ranked().process(PastRecordPostProcessor.PAST_RECORDS, relatedDocuments),
                requestSubject(context.getEvent()), requestWallClock(context), targetMarker);
    }

    /**
     * v1.0 (D3): the similar case lines of a bundle with the similarity search, in the past record form with the target
     * apart (A3-5); none for any other bundle.
     */
    List<PromptListItem> similarCaseItems(SecurityPromptBuildContext context) {
        List<Document> similarCases = context.getSimilarCases() != null ? context.getSimilarCases() : List.of();
        if (similarCases.isEmpty()) {
            return List.of();
        }
        return PastRecordLines.items(
                PastRecordPostProcessor.ranked().process(PastRecordPostProcessor.PAST_RECORDS, similarCases),
                requestSubject(context.getEvent()), requestWallClock(context), PastRecordLines.TARGET_APART);
    }

    /**
     * W6-12: the stored IDs of the past records the PAST RECORDS block drew, one per drawn line in the block's order
     * and within the entry's list cap, as the renderer draws them, by the PAST RECORDS entry of the given dictionary
     * (K5); none when the budget took the entry out.
     */
    List<String> drawnPastRecordIds(SecurityPromptBuildContext context, Set<PromptDictionaryEntry> withheld,
                                    List<PromptDictionaryEntry> dictionary) {
        PromptDictionaryEntry entry = dictionary.stream()
                .filter(candidate -> candidate.block() == PromptBlock.PAST_RECORDS
                        && "PastRecord{i}".equals(candidate.name()))
                .findFirst().orElse(null);
        if (entry == null || (withheld != null && withheld.contains(entry))) {
            return List.of();
        }
        List<PromptListItem> items = entry.listOrder().sort(pastRecordItems(context));
        return items.subList(0, PromptDictionaryRenderer.shownItems(entry, items.size())).stream()
                .map(PromptListItem::id).filter(StringUtils::hasText).toList();
    }

    /** BR-C8 (QF-16): whether the user prompt draws a past record: a PAST RECORDS or new SECOND PASS record line. */
    static boolean drawsPastRecords(String userText) {
        if (!StringUtils.hasText(userText)) {
            return false;
        }
        for (String line : userText.split("\n")) {
            PromptDictionaryLine drawn = PromptDictionaryLine.parse(line);
            if (drawn != null && DICTIONARY_PAST_RECORD_LABEL.matcher(drawn.label()).matches()) {
                return true;
            }
        }
        return false;
    }

    /** Writes on the event whether its past records reached the prompt the model gets (BR-C8, QF-16). */
    private static void markPastRecordProjection(SecurityEvent event, boolean projected) {
        if (event == null) {
            return;
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null) {
            metadata = new LinkedHashMap<>();
            event.setMetadata(metadata);
        }
        metadata.put(RAG_PROJECTED_TO_FINAL_PROMPT, projected);
    }

    /** The user's recent decisions that did not allow as PastDeniedDecision lines (W5-4), the latest first. */
    List<PromptListItem> pastDeniedItems(SecurityPromptBuildContext context) {
        return pastDeniedItems(context, false);
    }

    /** The PastDeniedDecision lines; a v21 line writes its target apart (A3-5). */
    List<PromptListItem> pastDeniedItems(SecurityPromptBuildContext context, boolean targetsApart) {
        return PastDeniedLines.items(pastDeniedDecisions(context), requestWallClock(context), targetsApart);
    }

    /** The recent decisions that did not allow the lookup left on the event (W5-4), none without a lookup. */
    PastDeniedDecisions pastDeniedDecisions(SecurityPromptBuildContext context) {
        SecurityEvent event = context.getEvent();
        return PastDeniedDecisions.fromMetadata(event != null && event.getMetadata() != null
                ? event.getMetadata().get(PastDeniedDecisions.EVENT_METADATA_KEY) : null);
    }

    /**
     * The counted past record facts of the exact lookup (W3-18) as their dictionary line, times measured from the
     * request; null when no lookup counted them.
     */
    String pastRecordCountsLine(SecurityPromptBuildContext context) {
        PastRecordCounts counts = pastRecordCounts(context);
        return counts != null ? counts.line(requestWallClock(context)) : null;
    }

    /** The counted past record facts of the exact lookup (W3-18), or null when no lookup counted them. */
    PastRecordCounts pastRecordCounts(SecurityPromptBuildContext context) {
        SecurityEvent event = context.getEvent();
        return PastRecordCounts.fromMetadata(event != null && event.getMetadata() != null
                ? event.getMetadata().get(PastRecordCounts.EVENT_METADATA_KEY) : null);
    }

    /** The request's time on the event clock (W3-13): the observed time, else the event's, null without either. */
    private static LocalDateTime requestWallClock(SecurityPromptBuildContext context) {
        CanonicalSecurityContext canonical = context.getCanonicalSecurityContext();
        Instant at = canonical != null && canonical.getRequestObservedAt() != null
                ? canonical.getRequestObservedAt()
                : context.getEvent() != null ? context.getEvent().getTimestamp() : null;
        return at != null ? LocalDateTime.ofInstant(at, EventTimeZone.get()) : null;
    }

    private void putRagMetadata(
            SecurityEvent event,
            boolean searchExecuted,
            String retrievalState,
            String absenceReason,
            String projectionState,
            String applicability,
            String ragRelevance,
            int relatedDocumentCount,
            boolean permissionFiltered) {
        if (event == null) {
            return;
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null) {
            metadata = new LinkedHashMap<>();
            event.setMetadata(metadata);
        }
        metadata.put("ragSearchExecuted", searchExecuted);
        metadata.put("ragRetrievalState", retrievalState);
        metadata.put("relatedDocumentCount", relatedDocumentCount);
        metadata.put("relatedDocumentsCount", relatedDocumentCount);
        metadata.put("ragProjectionState", projectionState);
        metadata.put("ragApplicability", applicability);
        metadata.put("ragRelevance", ragRelevance);
        metadata.put("ragPermissionFiltered", permissionFiltered);
        metadata.put("ragProjectedToFinalPrompt", relatedDocumentCount > 0);
        metadata.put("ragStatusProjectedToFinalPrompt", true);
        if (StringUtils.hasText(absenceReason)) {
            metadata.put("ragAbsenceReason", absenceReason);
        }
        else {
            metadata.remove("ragAbsenceReason");
        }
    }

    private SecurityPromptBuildContext createBuildContext(SecurityEvent event,
                                                          SessionContext sessionContext,
                                                          BehaviorAnalysis behaviorAnalysis,
                                                          List<Document> retrievedDocuments,
                                                          PromptBudgetProfile budgetProfile,
                                                          StructuredOutputMode structuredOutputMode) {
        // v1.0 (D3): the similar cases are drawn apart; everything else the past records give is the exact lookup's.
        List<Document> relatedDocuments = SimilarCases.exact(retrievedDocuments);
        List<Document> similarCases = SimilarCases.similar(retrievedDocuments);
        String userId = extractUserId(sessionContext);
        DetectedPatterns patterns = collectDetectedPatterns(relatedDocuments, userId, requestSubject(event));
        CanonicalSecurityContext canonicalSecurityContext = resolveCanonicalSecurityContext(event).orElse(null);
        cacheCanonicalSecurityContext(event, canonicalSecurityContext);
        if (canonicalSecurityContext != null) {
            event.addMetadata("sealedEvidence.canonicalContext", canonicalSecurityContext);
        }
        enrichPatternsFromBaseline(patterns, behaviorAnalysis);
        LearningContextEvidence learningContextEvidence = learningContextEvidenceAssembler.assemble(
                userId,
                event,
                canonicalSecurityContext,
                behaviorAnalysis,
                relatedDocuments);
        if (behaviorAnalysis != null) {
            behaviorAnalysis.setLearningContextEvidence(learningContextEvidence);
        }
        // The sealed context states the usual-behaviour view the prompt used: the work profile's view with the personal
        // baseline's state and dimensions, not the view before they were added (W2-3, P2 correction 9).
        if (canonicalSecurityContext != null && canonicalSecurityContext.getWorkProfile() != null
                && learningContextEvidence != null && learningContextEvidence.baselineView() != null) {
            canonicalSecurityContext.getWorkProfile().setBaselineView(learningContextEvidence.baselineView());
        }
        // The changes of device and network within the session the narrative found (W2-14); a value already set stays.
        CanonicalSecurityContext.SessionNarrativeProfile narrative = canonicalSecurityContext != null
                ? canonicalSecurityContext.getSessionNarrativeProfile() : null;
        if (behaviorAnalysis != null && narrative != null) {
            if (!StringUtils.hasText(behaviorAnalysis.getSessionDeviceChange())) {
                behaviorAnalysis.setSessionDeviceChange(narrative.getSessionDeviceChange());
            }
            if (!StringUtils.hasText(behaviorAnalysis.getSessionNetworkChange())) {
                behaviorAnalysis.setSessionNetworkChange(narrative.getSessionNetworkChange());
            }
        }
        // A new device is this device compared with the user's observed devices; a value the host declared stays.
        if (canonicalSecurityContext != null && canonicalSecurityContext.getSession() != null
                && canonicalSecurityContext.getSession().getNewDevice() == null && learningContextEvidence != null) {
            canonicalSecurityContext.getSession().setNewDevice(learningContextEvidence.deviceOutsideObserved());
        }
        // The decision facts are computed once, from the context and evidence this prompt is built from (W2-5).
        if (canonicalSecurityContext != null) {
            canonicalSecurityContext.setDecisionFacts(DecisionFactsResolver.resolve(
                    canonicalSecurityContext, learningContextEvidence, EventTimeZone.get()));
        }
        BaselineStatus baselineStatus = determineBaselineStatus(event, behaviorAnalysis, learningContextEvidence);
        return new SecurityPromptBuildContext(
                event,
                sessionContext,
                behaviorAnalysis,
                relatedDocuments,
                similarCases,
                canonicalSecurityContext,
                userId,
                baselineStatus,
                patterns,
                learningContextEvidence,
                budgetProfile,
                structuredOutputMode != null ? structuredOutputMode : StructuredOutputMode.VALIDATED_CONVERTER,
                List.of()
        );
    }

    private PromptRuntimeGovernanceRuleContext promptRuntimeGovernanceRuleContext(
            PromptGovernanceResolutionContext resolutionContext,
            PromptGovernanceDescriptor resolvedDescriptor) {
        PromptGovernanceDescriptor descriptor = resolvedDescriptor != null
                ? resolvedDescriptor
                : defaultDescriptor;
        Map<String, Object> attributes = new LinkedHashMap<>(resolutionContext.attributes());
        attributes.put("registryScope", resolutionContext.registryScope());
        attributes.put("promptKey", descriptor.promptKey());
        attributes.put("templateKey", descriptor.templateKey());
        attributes.put("promptVersion", descriptor.promptVersion());
        attributes.put("contractVersion", descriptor.contractVersion());
        return new PromptRuntimeGovernanceRuleContext(
                resolutionContext.registryScope(),
                descriptor.promptKey(),
                descriptor.promptVersion(),
                resolutionContext.tenantId(),
                resolutionContext.resourceId(),
                resolutionContext.resourceUrl(),
                resolutionContext.httpMethod(),
                Map.copyOf(attributes));
    }

    private Map<String, Object> buildPromptRuntimeGovernanceMetadata(
            List<PromptRuntimeGovernanceRule> rules,
            PromptRuntimeGovernanceRuleApplicationResult result) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        List<PromptRuntimeGovernanceRule> safeRules = rules != null ? rules : List.of();
        List<PromptRuntimeGovernanceRuleApplication> applications =
                result == null || result.applications() == null ? List.of() : result.applications();
        List<String> ruleIds = safeRules.stream()
                .map(PromptRuntimeGovernanceRule::ruleId)
                .filter(StringUtils::hasText)
                .toList();
        List<String> applicationRuleIds = applications.stream()
                .map(PromptRuntimeGovernanceRuleApplication::ruleId)
                .filter(StringUtils::hasText)
                .toList();
        List<String> appliedRuleIds = applications.stream()
                .filter(PromptRuntimeGovernanceRuleApplication::changedPrompt)
                .map(PromptRuntimeGovernanceRuleApplication::ruleId)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        metadata.put("promptRuntimeGovernanceRuleCount", safeRules.size());
        metadata.put("promptRuntimeGovernanceRuleIds", ruleIds);
        metadata.put("promptRuntimeGovernanceApplicationRuleIds", applicationRuleIds);
        metadata.put("promptRuntimeGovernanceAppliedRuleIds", appliedRuleIds);
        metadata.put("promptRuntimeGovernanceAppliedCount", applications.stream()
                .filter(PromptRuntimeGovernanceRuleApplication::changedPrompt)
                .count());
        metadata.put("promptRuntimeGovernanceApplicationStates", applications.stream()
                .map(this::promptRuntimeGovernanceApplicationMetadata)
                .toList());
        return metadata;
    }

    private Map<String, Object> promptRuntimeGovernanceApplicationMetadata(
            PromptRuntimeGovernanceRuleApplication application) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (application == null) {
            return metadata;
        }
        metadata.put("ruleId", application.ruleId());
        metadata.put("sourceActionId", application.sourceActionId());
        metadata.put("slotKey", application.slotKey());
        metadata.put("ruleType", application.ruleType());
        metadata.put("appliedOperation", application.appliedOperation());
        metadata.put("resultState", application.resultState());
        metadata.put("changedPrompt", application.changedPrompt());
        metadata.put("beforePromptHash", application.beforePromptHash());
        metadata.put("afterPromptHash", application.afterPromptHash());
        return metadata;
    }

    private Map<String, Object> buildPqaPromptCacheMetadata(
            String systemText,
            PromptBudgetProfile budgetProfile,
            CachedRenderedPromptSections cachedSystemSections,
            String userText,
            long renderTimeMs) {
        // The in-process cache of the rendered system sections; the provider's prompt cache is recorded apart
        // (promptCacheKey, promptCacheHit, cachedPromptTokens) so the two are not read as one (W3-8).
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptRenderCacheSystemStable", true);
        metadata.put("promptRenderCacheSystemHash", PromptGovernanceSupport.sha256(systemText != null ? systemText : ""));
        metadata.put("promptRenderCacheKey", cachedSystemSections != null ? cachedSystemSections.cacheKey() : null);
        metadata.put("promptRenderCacheHit", cachedSystemSections != null && cachedSystemSections.cacheHit());
        metadata.put("promptRuntimeSlotCount", countPromptSlotLines(userText));
        metadata.put("promptRuntimeRenderTimeMs", renderTimeMs);
        metadata.put("promptRenderCacheContextMode", "FULL_FIELD_PRESERVED");
        return metadata;
    }

    /**
     * The provider prompt cache key (W3-8): the hash of the system prompt as the model gets it, the long prefix every
     * request shares, so the requests that share it go to the same provider cache whoever sends them. A key per user
     * split that cache on the real server (each user's first requests found nothing cached), and the user's baseline
     * block changes with each learned request anyway. The key carries no user and no tenant.
     */
    private static String promptCacheKey(String modelSystemPrompt) {
        return PROMPT_CACHE_KEY_PREFIX
                + PromptBundleHashes.sha256Hex(modelSystemPrompt != null ? modelSystemPrompt : "").substring(0, 32);
    }

    private Map<String, Object> buildRagPromptMetadata(SecurityPromptBuildContext buildContext) {
        if (buildContext == null) {
            return Map.of();
        }
        SecurityEvent event = buildContext.getEvent();
        Map<String, Object> eventMetadata = event != null ? event.getMetadata() : null;
        Map<String, Object> metadata = new LinkedHashMap<>();
        int relatedDocumentCount = buildContext.getRelatedDocuments() != null
                ? buildContext.getRelatedDocuments().size()
                : 0;
        metadata.put("ragSearchExecuted", metadataBoolean(eventMetadata, "ragSearchExecuted") || relatedDocumentCount > 0);
        metadata.put("relatedDocumentCount", relatedDocumentCount);
        metadata.put("relatedDocumentsCount", relatedDocumentCount);
        copyMetadataValue(metadata, eventMetadata, "ragRetrievalState");
        copyMetadataValue(metadata, eventMetadata, "ragAbsenceReason");
        copyMetadataValue(metadata, eventMetadata, "ragProjectionState");
        copyMetadataValue(metadata, eventMetadata, "ragPermissionFiltered");
        copyMetadataValue(metadata, eventMetadata, "ragCandidateDocumentCount");
        copyMetadataValue(metadata, eventMetadata, "ragAuthorizedDocumentCount");
        copyMetadataValue(metadata, eventMetadata, "ragDeniedDocumentCount");
        copyMetadataValue(metadata, eventMetadata, "ragProjectedToFinalPrompt");
        copyMetadataValue(metadata, eventMetadata, "ragStatusProjectedToFinalPrompt");
        return metadata;
    }

    private void copyMetadataValue(Map<String, Object> target, Map<String, Object> source, String key) {
        if (target == null || source == null || key == null) {
            return;
        }
        Object value = source.get(key);
        if (value != null) {
            target.put(key, value);
        }
    }

    private CachedRenderedPromptSections composeSystemSections(
            SecurityPromptBuildContext buildContext,
            PromptBudgetProfile budgetProfile,
            SecurityDecisionPromptBundles.Bundle bundle) {
        AssembledPrompt version = promptVersionOf(buildContext != null ? buildContext.getEvent() : null);
        // Plan 6-2: the version's parts draw the v1.0 text, so its content hash keys the cache with the bundle.
        String cacheKey = systemSectionsCacheKey(buildContext, budgetProfile, bundle.version())
                + "|" + version.contentHash()
                + (SecurityDecisionVersionFeatures.of(version).agentVariesSystemText() && agentRequest(buildContext)
                ? "|AGENT" : "");
        RenderedPromptSections cached = systemSectionsCache.getIfPresent(cacheKey);
        if (cached != null) {
            return new CachedRenderedPromptSections(cacheKey, true, cached);
        }
        RenderedPromptSections rendered = composeSections(SYSTEM_SECTION_PLANS, buildContext);
        systemSectionsCache.put(cacheKey, rendered);
        return new CachedRenderedPromptSections(cacheKey, false, rendered);
    }

    private String systemSectionsCacheKey(SecurityPromptBuildContext buildContext, PromptBudgetProfile budgetProfile,
                                          String bundleVersion) {
        PromptBudgetProfile effectiveProfile = budgetProfile != null
                ? budgetProfile
                : PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT;
        StructuredOutputMode outputMode = buildContext != null
                ? buildContext.getStructuredOutputMode()
                : StructuredOutputMode.VALIDATED_CONVERTER;
        return String.join("|",
                defaultDescriptor.promptKey(),
                bundleVersion,
                effectiveProfile.profileKey(),
                outputMode.name(),
                "PROFILE_FULL",
                String.valueOf(minimumActionSettings),
                minimumActionMode);
    }

    private int countPromptSlotLines(String userText) {
        if (!StringUtils.hasText(userText)) {
            return 0;
        }
        int count = 0;
        for (String line : userText.split("\\R")) {
            if (line != null && line.contains(":") && !line.stripLeading().startsWith("#")) {
                count++;
            }
        }
        return count;
    }

    /**
     * Whether the fact values stay whole while the prompt is built (W3-7): the dictionary forbids cutting every entry
     * but untrusted text, which is cut by its own rule (W3-6). A length limit then cuts no fact.
     */
    static boolean factValuesStayWhole(List<PromptDictionaryEntry> entries) {
        return entries.stream()
                .filter(entry -> entry.block() != PromptBlock.UNTRUSTED_TEXT)
                .noneMatch(PromptDictionaryEntry::truncationAllowed);
    }

    /**
     * The system prompt as the model gets it (W3-7): the composed system text, then its output format when the
     * structured output is not native, assembled as the template assembles it (the template adds no context).
     */
    static String modelSystemPrompt(String composedSystemPrompt, StructuredOutputMode structuredOutputMode) {
        return AbstractStandardPromptTemplate.assembleSystemPrompt(composedSystemPrompt != null ? composedSystemPrompt : "",
                structuredOutputMode != StructuredOutputMode.NATIVE_STRUCTURED
                        ? SecurityDecisionContractSectionBuilder.formatInstructions() : null,
                null);
    }

    /**
     * V-4: the decision facts of a v21 prompt, computed again in the records notation from the same context and
     * evidence. The comparisons and record checks are the same as before; only their lines leave the core's
     * conclusions out, so the sealed context keeps the facts the v21 prompt stated.
     */
    private static void restateDecisionFactsAsRecords(SecurityPromptBuildContext buildContext) {
        CanonicalSecurityContext canonical = buildContext != null ? buildContext.getCanonicalSecurityContext() : null;
        if (canonical == null) {
            return;
        }
        canonical.setDecisionFacts(DecisionFactsResolver.resolve(canonical, buildContext.getLearningContextEvidence(),
                EventTimeZone.get(), DecisionFactsResolver.Notation.RECORDS));
    }

    /** Whether a v20 prompt over its budget takes entries out (W3-7); by default the budget is only observed. */
    private boolean budgetEnforced() {
        return tieredStrategyProperties != null
                && tieredStrategyProperties.getPromptRuntime().getBudgetEnforcement()
                == TieredStrategyProperties.PromptRuntime.BudgetEnforcement.ENFORCE;
    }

    /**
     * The v20 user prompt: the dictionary blocks drawn from the same build context. A block left out is the
     * dictionary's missing notation, not an omission.
     */
    private RenderedPromptSections composeDictionaryBlocks(SecurityPromptBuildContext context, String systemText,
                                                           PromptBudgetProfile budgetProfile, String modelHint,
                                                           DictionaryKit kit) {
        long startedNanos = System.nanoTime();
        PromptDictionaryRenderer renderer = kit.renderer();
        List<PromptDictionaryEntry> entries = kit.entries();
        PromptEntryValues values = SecurityDecisionPromptValues.of(this, context, renderer.values(),
                EventTimeZone.get());
        Set<PromptDictionaryEntry> withheld = new LinkedHashSet<>();
        PromptDictionaryRendering rendering = renderer.render(values, withheld);
        List<PromptOmissionRecord> trimmed = new ArrayList<>();
        Integer trimmedTotal = null;
        if (budgetEnforced() && budgetProfile != null) {
            // W3-7: over the budget, entries leave by dictionary priority; a required entry stays and no value is cut.
            // The count is the one the reported budget uses: the system prompt as the model gets it, the request's
            // model hint.
            PromptTokenEstimator estimator = PromptTokenEstimatorRegistry.defaultRegistry().resolve(modelHint);
            PromptDictionaryRendering full = rendering;
            List<PromptDictionaryEntry> taken = PromptBudgetTrim.withhold(
                    PromptBudgetTrim.order(entries, drawnEntries(full, entries)),
                    candidate -> estimator.estimate(modelHint, systemText,
                            renderer.render(values, candidate).text(), budgetProfile).budgetExceeded());
            PromptTokenEstimate estimate = estimator.estimate(modelHint, systemText, full.text(), budgetProfile);
            for (PromptDictionaryEntry entry : taken) {
                withheld.add(entry);
                PromptDictionaryRendering next = renderer.render(values, withheld);
                PromptTokenEstimate nextEstimate = estimator.estimate(modelHint, systemText, next.text(), budgetProfile);
                trimmed.add(new PromptOmissionRecord(entry.block().name() + "." + entry.name(),
                        PromptOmissionType.BUDGET_TRIMMED, entryLines(full, entry, entries),
                        Math.max(0, estimate.estimatedUserTokens() - nextEstimate.estimatedUserTokens()),
                        "Taken out to fit the prompt budget by dictionary priority " + entry.priority() + ".",
                        semanticRisk(PromptSectionPriorityClass.valueOf(entry.priority()))));
                rendering = next;
                estimate = nextEstimate;
            }
            trimmedTotal = taken.isEmpty() ? null : estimate.estimatedTotalTokens();
        }
        // W3-13: the decision facts the sealed context keeps carry the fact IDs this prompt drew.
        CanonicalSecurityContext canonical = context.getCanonicalSecurityContext();
        if (canonical != null && canonical.getDecisionFacts() != null) {
            canonical.setDecisionFacts(canonical.getDecisionFacts().withPromptIds(rendering.factIds()));
        }
        List<String> blockKeys = rendering.blocks().stream().map(PromptBlock::title).toList();
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (trimmedTotal != null) {
            metadata.put("promptBudgetTrimmedTotalTokens", trimmedTotal);
        }
        // What the prompt inspector compares the drawn lines with and the sealed package would not otherwise keep: the
        // clock the times were drawn on, the retrieval state of the block, the counted past record facts the counts line
        // was drawn from (W3-18) and the baseline state the evidence and status lines state (W3-19). The fact ids are
        // on the lines themselves; no check reads a separate map of them (R1b-10).
        metadata.put(PromptExecutionMetadata.EVENT_TIME_ZONE, EventTimeZone.get().getId());
        metadata.put(PromptExecutionMetadata.PROMPT_RAG_STATE, ragState(context).toMetadata());
        PastRecordCounts counts = pastRecordCounts(context);
        if (counts != null) {
            metadata.put(PromptExecutionMetadata.PROMPT_PAST_RECORD_COUNTS, counts.toMetadata());
        }
        // W6-12: which stored records the model was given, so a seal names them and not only how many.
        // K5: the render names its past records by its own dictionary's entry.
        metadata.put(PromptExecutionMetadata.PROMPT_PAST_RECORD_IDS, drawnPastRecordIds(context, withheld, entries));
        PastDeniedDecisions denied = pastDeniedDecisions(context);
        if (!denied.entries().isEmpty()) {
            metadata.put(PromptExecutionMetadata.PROMPT_PAST_DENIED_DECISIONS, denied.toMetadata());
        }
        String baselineState = SecurityDecisionPromptValues.baselineState(this, context);
        if (baselineState != null) {
            metadata.put(PromptExecutionMetadata.PROMPT_BASELINE_STATUS, baselineState);
        }
        // W4-7 (inventory 6 bundle 10): the facts the UNKNOWN block names are the completeness reasons.
        metadata.put(PROMPT_EVIDENCE_COMPLETENESS_REASONS, rendering.unknownFacts());
        return new RenderedPromptSections(rendering.text(), blockKeys, List.copyOf(trimmed),
                Map.of(kit.layoutName(), elapsedMicros(startedNanos)),
                Collections.unmodifiableMap(metadata));
    }

    /**
     * The SECOND PASS block of a Layer2 second pass (W3-9): the first pass's verdict, the uncertain fact this pass
     * gathered (by its dictionary name: the second pass block carries no fact IDs) and the past records only this pass found.
     */
    private RenderedPromptSections composeSecondPass(SecurityPromptBuildContext context, SecondPass secondPass,
                                                     DictionaryKit kit) {
        long startedNanos = System.nanoTime();
        PromptDictionaryRenderer renderer = kit.renderer();
        // E-4b: a first pass that retrieved its own past records gets none as new (Layer2's rule); the past records of
        // this pass's search are then not what the first pass lacked.
        boolean firstRetrieved = firstPassRetrieved(secondPass.firstPastRecordsState());
        // A3-5: the second pass block has no untrusted text, so a record line does not show the requester's target.
        List<PromptListItem> records = firstRetrieved ? List.of()
                : pastRecordItems(context, PastRecordLines.TARGET_WITHHELD);
        PromptEntryValues.Builder values = renderer.values();
        values.value(PromptBlock.SECOND_PASS, "FirstPassVerdict", secondPass.firstVerdict());
        values.value(PromptBlock.SECOND_PASS, "NewlyKnown", firstRetrieved
                ? "PastRecord{i}: none new (first pass: retrieved, " + secondPass.firstPastRecordsState() + ")"
                : "PastRecord{i}: " + records.size() + " found (first pass: not retrieved, "
                        + secondPass.firstPastRecordsState() + ")");
        values.lines(PromptBlock.SECOND_PASS, "NewPastRecord{i}", records);
        values.headerQualifier(PromptBlock.SECOND_PASS, "only the facts gathered after the first pass");
        values.timeZone(EventTimeZone.get());
        if (records.stream().anyMatch(record -> !record.text().startsWith(PastRecordLines.TIME_NOT_RECORDED))) {
            values.clocked(PromptBlock.SECOND_PASS, "NewPastRecord{i}");
        }
        Set<PromptDictionaryEntry> otherBlocks = new LinkedHashSet<>();
        for (PromptDictionaryEntry entry : kit.entries()) {
            if (entry.block() != PromptBlock.SECOND_PASS) {
                otherBlocks.add(entry);
            }
        }
        PromptDictionaryRendering rendering = renderer.render(values.build(), otherBlocks);
        return new RenderedPromptSections(rendering.text(), List.of(PromptBlock.SECOND_PASS.title()), List.of(),
                Map.of(SECOND_PASS_LAYOUT, elapsedMicros(startedNanos)),
                Map.of("layer2SecondPass", true,
                        "layer2NewlyKnown", List.of("PastRecord{i}"),
                        "layer2FirstPassVerdict", secondPass.firstVerdict()));
    }

    /** Whether the first pass's past record search ran to an answer (records or none), not one it could not get. */
    private static boolean firstPassRetrieved(String state) {
        return StringUtils.hasText(state)
                && !PastRecordLineValues.NOT_RETRIEVED_STATES.contains(state.trim().toUpperCase(Locale.ROOT));
    }

    /** A Layer2 second pass: the first v20 prompt as it was sent, the first verdict and its past record state. */
    record SecondPass(String firstUserPrompt, String firstVerdict, String firstPastRecordsState) {

        static SecondPass of(String firstUserPrompt, String firstVerdict, String firstPastRecordsState) {
            return StringUtils.hasText(firstUserPrompt) && StringUtils.hasText(firstVerdict)
                    ? new SecondPass(firstUserPrompt, firstVerdict, firstPastRecordsState)
                    : null;
        }
    }

    /** The dictionary entries a rendering drew, by the labels of its lines. */
    private static List<PromptDictionaryEntry> drawnEntries(PromptDictionaryRendering rendering,
                                                            List<PromptDictionaryEntry> entries) {
        Set<PromptDictionaryEntry> drawn = new LinkedHashSet<>();
        for (PromptSlot slot : rendering.slots()) {
            PromptDictionaryEntry entry = dictionaryEntryOf(slot.label(), entries);
            if (entry != null) {
                drawn.add(entry);
            }
        }
        return List.copyOf(drawn);
    }

    private static int entryLines(PromptDictionaryRendering rendering, PromptDictionaryEntry entry,
                                  List<PromptDictionaryEntry> entries) {
        return (int) rendering.slots().stream()
                .filter(slot -> entry.equals(dictionaryEntryOf(slot.label(), entries))).count();
    }

    private static PromptDictionaryEntry dictionaryEntryOf(String label, List<PromptDictionaryEntry> entries) {
        if (label == null) {
            return null;
        }
        for (PromptDictionaryEntry entry : entries) {
            if (entry.name().equals(label) || (entry.indexed() && label.startsWith(entry.stem())
                    && label.length() > entry.stem().length()
                    && label.substring(entry.stem().length()).chars().allMatch(Character::isDigit))) {
                return entry;
            }
        }
        return null;
    }

    private RenderedPromptSections composeSections(List<PromptSectionPlan> plans, SecurityPromptBuildContext context) {
        StringBuilder composed = new StringBuilder();
        List<String> renderedSectionKeys = new ArrayList<>();
        List<PromptOmissionRecord> omissionLedger = new ArrayList<>();
        Map<String, Long> sectionTimings = new LinkedHashMap<>();
        for (PromptSectionPlan plan : plans) {
            long sectionStartedNanos = System.nanoTime();
            String section = plan.builder().build(this, context);
            sectionTimings.put(plan.sectionKey(), elapsedMicros(sectionStartedNanos));
            if (hasPromptContent(section)) {
                appendIfPresent(composed, section);
                renderedSectionKeys.add(plan.sectionKey());
                continue;
            }
            if (plan.trackAbsenceAsOmission()) {
                omissionLedger.add(new PromptOmissionRecord(
                        plan.sectionKey(),
                        PromptOmissionType.NOT_COLLECTED,
                        0,
                        0,
                        "No runtime evidence was available for this prompt section during composition.",
                        semanticRisk(plan.priorityClass())
                ));
            }
        }
        return new RenderedPromptSections(composed.toString(), renderedSectionKeys, omissionLedger, Map.copyOf(sectionTimings),
                Map.of());
    }

    private PromptBudgetProfile resolveBudgetProfile(SecurityEvent event, BehaviorAnalysis behaviorAnalysis) {
        PromptBudgetProfile layer1Fallback = PromptBudgetProfile.fromKey(
                tieredStrategyProperties != null && tieredStrategyProperties.getLayer1() != null
                        ? tieredStrategyProperties.getLayer1().getDefaultBudgetProfile()
                        : null,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
        PromptBudgetProfile layer2Fallback = PromptBudgetProfile.fromKey(
                tieredStrategyProperties != null && tieredStrategyProperties.getLayer2() != null
                        ? tieredStrategyProperties.getLayer2().getDefaultBudgetProfile()
                        : null,
                PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT);
        if (event != null && event.getMetadata() != null) {
            Object processingLayer = event.getMetadata().get("processingLayer");
            if (processingLayer instanceof Number number && number.intValue() >= 2) {
                return layer2Fallback;
            }
            if (processingLayer instanceof String value && ("2".equals(value.trim()) || value.toLowerCase(Locale.ROOT).contains("layer2"))) {
                return layer2Fallback;
            }
        }
        return layer1Fallback;
    }

    /**
     * v1.0 (plan 2.3 A11): every drawn line of a dictionary block is of its entry's form, by the rule the prompt
     * inspector's dictionary contract check reads (the entry's form, a list's overflow line, a missing value's text).
     */
    static SecurityPromptContractAudit withDictionaryFormViolations(SecurityPromptContractAudit audit, String userText,
                                                                     List<PromptDictionaryEntry> entries) {
        List<String> violations = new ArrayList<>(audit.violations());
        PromptBlock block = null;
        for (String line : userText.split("\n")) {
            if (PromptBlock.isHeaderLine(line)) {
                block = PromptBlock.fromSectionKey(line).orElse(null);
                continue;
            }
            PromptDictionaryLine drawn = PromptDictionaryLine.parse(line);
            if (drawn == null || block == null) {
                continue;
            }
            PromptBlock lineBlock = block;
            PromptDictionaryEntry entry = entries.stream()
                    .filter(candidate -> candidate.block() == lineBlock && candidate.matchesLabel(drawn.label()))
                    .findFirst().orElse(null);
            if (entry == null) {
                violations.add("V1_DICTIONARY_FORM:" + lineBlock.name() + "." + drawn.label() + " is no entry");
                continue;
            }
            boolean overflow = entry.indexed() && PromptDictionaryRenderer.OVERFLOW.matcher(drawn.value()).matches();
            boolean kept = overflow || entry.acceptsValue(drawn.value())
                    || (entry.missing() == PromptMissingNotation.RENDERED_VALUE && drawn.value().equals(entry.missingText()));
            if (!kept) {
                violations.add("V1_DICTIONARY_FORM:" + lineBlock.name() + "." + entry.name() + " is out of its form");
            }
        }
        return new SecurityPromptContractAudit(audit.renderedRequestSnapshot(), audit.renderedLearningSnapshot(),
                audit.renderedLabelMatrix(), audit.compactedLineCountBySection(), List.copyOf(violations));
    }

    private PromptEvidenceCompleteness evaluateCompleteness(
            SecurityPromptBuildContext buildContext,
            List<PromptOmissionRecord> omissionLedger,
            SecurityPromptContractAudit promptContractAudit,
            List<?> unknownFacts,
            boolean v1) {
        boolean requiredOmission = omissionLedger != null && omissionLedger.stream()
                .anyMatch(this::isCompletenessBlockingOmission);
        if (requiredOmission) {
            return PromptEvidenceCompleteness.INCOMPLETE;
        }
        CanonicalSecurityContext context = buildContext != null ? buildContext.getCanonicalSecurityContext() : null;
        LearningContextEvidence learningEvidence = buildContext != null ? buildContext.getLearningContextEvidence() : null;
        if (context == null
                || !CanonicalContextFieldPolicy.hasActorIdentity(context)
                || !CanonicalContextFieldPolicy.hasSessionIdentity(context)
                || !CanonicalContextFieldPolicy.hasResourceIdentity(context)) {
            return PromptEvidenceCompleteness.INCOMPLETE;
        }
        if (unknownFacts != null) {
            // W4-7 (inventory 6 bundle 10): a v20 prompt is partial when its UNKNOWN block names a fact; a contract
            // violation makes it incomplete only when nothing is unknown, in the order of the rule before.
            if (!unknownFacts.isEmpty()) {
                return PromptEvidenceCompleteness.PARTIAL;
            }
            if (!v1) {
                return promptContractAudit != null && !promptContractAudit.violations().isEmpty()
                        ? PromptEvidenceCompleteness.INCOMPLETE
                        : PromptEvidenceCompleteness.SUFFICIENT;
            }
            // v1.0 (plan 2.3 A12): the UNKNOWN block and the canonical field criteria are read together.
        }
        if (!CanonicalContextFieldPolicy.hasEffectiveRoles(context)
                || !CanonicalContextFieldPolicy.hasAuthorizationScope(context)
                || !CanonicalContextFieldPolicy.hasResourceSensitivity(context)
                || !CanonicalContextFieldPolicy.hasMfaState(context)
                || CanonicalContextFieldPolicy.hasProvisionalWorkProfile(context)
                || CanonicalContextFieldPolicy.hasProvisionalRoleScopeProfile(context)) {
            return PromptEvidenceCompleteness.PARTIAL;
        }
        ContextCoverageReport coverage = context.getCoverage();
        if (coverage != null && !coverage.missingCriticalFacts().isEmpty()) {
            return PromptEvidenceCompleteness.PARTIAL;
        }
        if (learningEvidence != null && !learningEvidence.carryMissingFacts().isEmpty()) {
            return PromptEvidenceCompleteness.PARTIAL;
        }
        if (promptContractAudit != null && !promptContractAudit.violations().isEmpty()) {
            return PromptEvidenceCompleteness.INCOMPLETE;
        }
        return PromptEvidenceCompleteness.SUFFICIENT;
    }

    private boolean isCompletenessBlockingOmission(PromptOmissionRecord omission) {
        if (omission == null) {
            return false;
        }
        PromptSectionPlan plan = SYSTEM_SECTION_PLANS.stream()
                .filter(candidate -> Objects.equals(candidate.sectionKey(), omission.sectionKey()))
                .findFirst()
                .orElse(null);
        if (plan != null) {
            return !plan.omittable() && plan.priorityClass() == PromptSectionPriorityClass.P0_REQUIRED;
        }
        return omission.semanticRisk() == PromptSemanticRisk.CRITICAL
                || omission.semanticRisk() == PromptSemanticRisk.HIGH;
    }

    private Map<String, Object> buildPromptContractMetadata(SecurityPromptContractAudit promptContractAudit) {
        if (promptContractAudit == null) {
            return Map.of();
        }
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("renderedRequestSnapshot", promptContractAudit.renderedRequestSnapshot());
        metadata.put("renderedLearningSnapshot", promptContractAudit.renderedLearningSnapshot());
        metadata.put("renderedLabelMatrix", promptContractAudit.renderedLabelMatrix());
        metadata.put("compactedLineCountBySection", promptContractAudit.compactedLineCountBySection());
        metadata.put("promptContractViolations", promptContractAudit.violations());
        metadata.put("promptContractViolationCount", promptContractAudit.violations().size());
        return metadata;
    }

    private List<String> mergeSectionKeys(List<String> systemSections, List<String> userSections) {
        LinkedHashSet<String> merged = new LinkedHashSet<>();
        if (systemSections != null) {
            merged.addAll(systemSections);
        }
        if (userSections != null) {
            merged.addAll(userSections);
        }
        return List.copyOf(merged);
    }

    private PromptSemanticRisk semanticRisk(PromptSectionPriorityClass priorityClass) {
        if (priorityClass == null) {
            return PromptSemanticRisk.MEDIUM;
        }
        return switch (priorityClass) {
            case P0_REQUIRED -> PromptSemanticRisk.CRITICAL;
            case P1_HIGH_VALUE -> PromptSemanticRisk.HIGH;
            case P2_SUPPORTING -> PromptSemanticRisk.MEDIUM;
            case P3_OPTIONAL -> PromptSemanticRisk.LOW;
        };
    }

    private Map<String, Object> buildLearningPromptMetadata(
            SecurityPromptBuildContext buildContext,
            List<String> sectionSet) {
        LearningContextEvidence learningEvidence = buildContext != null ? buildContext.getLearningContextEvidence() : null;
        if (learningEvidence == null) {
            return Map.of();
        }
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("learningPersonalBaselineEstablished",
                learningEvidence.personalBaseline() != null && learningEvidence.personalBaseline().established());
        metadata.put("learningSupportingBaselineAvailable",
                learningEvidence.supportingBaseline() != null && learningEvidence.supportingBaseline().available());
        metadata.put("supportingBaselineUsed",
                learningEvidence.supportingBaseline() != null
                        && learningEvidence.supportingBaseline().available()
                        && ((learningEvidence.personalBaseline() == null || !learningEvidence.personalBaseline().established())
                        || learningEvidence.personalRetrievedEvidence().isEmpty()));
        metadata.put("personalRetrievedDocCount", learningEvidence.personalRetrievedEvidence().size());
        metadata.put("supportingRetrievedDocCount", learningEvidence.supportingRetrievedEvidence().size());
        metadata.put("supportingComparableCount", learningEvidence.supportingComparableCount());
        metadata.put("learningCarryRequiredFacts", learningEvidence.carryRequiredFacts());
        metadata.put("learningCarryMissingFacts", learningEvidence.carryMissingFacts());
        metadata.put("renderedDeltaCount", learningEvidence.currentVsObservedDeltas().size());
        CurrentVsObservedDeltaSnapshot strongestDelta = learningEvidence.strongestDelta();
        if (strongestDelta != null && StringUtils.hasText(strongestDelta.description())) {
            metadata.put("strongestLearningDelta", strongestDelta.description());
        }
        metadata.put("historicalComparableCount", learningEvidence.historicalComparableCount());
        metadata.put("observedPatternEvidenceScope", learningEvidence.observedPatternEvidenceScope());
        metadata.put("historicalComparableScope", learningEvidence.historicalComparableScope());
        metadata.put("currentRequestCombinationSeenCount",
                learningEvidence.personalRetrievedEvidence().isEmpty()
                        ? "UNKNOWN"
                        : learningEvidence.currentRequestCombinationSeenCount());
        metadata.put("currentRequestCombinationEvidenceScope",
                learningEvidence.currentRequestCombinationEvidenceScope());
        if (StringUtils.hasText(learningEvidence.currentRequestCombinationComparedDimensions())) {
            metadata.put("currentRequestCombinationComparedDimensions",
                    learningEvidence.currentRequestCombinationComparedDimensions());
        }
        if (StringUtils.hasText(learningEvidence.currentRequestClosestObservedOverlap())) {
            metadata.put("currentRequestClosestObservedOverlap",
                    learningEvidence.currentRequestClosestObservedOverlap());
        }
        if (StringUtils.hasText(learningEvidence.strongestCurrentRequestCombinationDelta())) {
            metadata.put("strongestCurrentRequestCombinationDelta",
                    learningEvidence.strongestCurrentRequestCombinationDelta());
        }
        if (StringUtils.hasText(learningEvidence.currentRequestCombinationSummary())) {
            metadata.put("currentRequestCombinationSummary",
                    learningEvidence.currentRequestCombinationSummary());
        }
        if (StringUtils.hasText(learningEvidence.representativeCombinationSummary())) {
            metadata.put("observedComparableCombination1",
                    learningEvidence.representativeCombinationSummary());
        }
        metadata.put("learningSectionPresent",
                sectionSet != null
                        && (sectionSet.contains(SecurityPromptSectionCatalog.OBSERVED_AND_PERSONAL_WORK_PATTERN)
                        || sectionSet.contains(SecurityPromptSectionCatalog.SUPPORTING_LEARNING_CONTEXT)));
        metadata.put("supportingLearningSectionPresent",
                sectionSet != null && sectionSet.contains(SecurityPromptSectionCatalog.SUPPORTING_LEARNING_CONTEXT));
        return metadata;
    }

    String extractUserId(SessionContext sessionContext) {
        return (sessionContext != null) ? sessionContext.getUserId() : null;
    }

    /** Whether an agent sends the request (A1-3): the system text leaves the automation boundary out for it. */
    static boolean agentRequest(SecurityPromptBuildContext context) {
        return context != null && AgentLineValues.agent(context.getCanonicalSecurityContext()) != null;
    }

    /**
     * W4-4: the host's minimum action rule settings (dictionary 6) the system text states; defaults when null. A
     * cached system text of other settings is not served (the settings are part of the cache key).
     */
    public void setMinimumActionSettings(MinimumActionRules.Settings settings) {
        this.minimumActionSettings = settings != null ? settings : MinimumActionRules.Settings.DEFAULTS;
        systemSectionsCache.invalidateAll();
    }

    /**
     * Plan 6-2, 6-3: the store the version a selector chooses or an event names is read from (the database versions,
     * plan 3.8 11); the product versions when null.
     */
    public void setPromptVersionStore(PromptVersionStore store) {
        this.promptVersionStore = store != null ? store : SecurityDecisionPromptDocument.productStore();
        systemSectionsCache.invalidateAll();
    }

    /**
     * The version of the security decision prompt the event runs (plan 3.4): the one fixed on the event when its
     * decision started; an event whose decision has not chosen one yet chooses it now and keeps it. The product version
     * without an event, or when the store cannot find the fixed one.
     */
    public AssembledPrompt promptVersionOf(SecurityEvent event) {
        if (event == null) {
            return SecurityDecisionPromptDocument.product();
        }
        return fixedOn(event).orElseGet(() -> selectBundle(event, promptGovernanceResolutionContext(event))).version();
    }

    /**
     * K32 (decision D10): the settings and whether the host enforces them; an enforced floor is stated by the system
     * text, as the response check holds an answer to it.
     */
    public void setMinimumActionSettings(MinimumActionRules.Settings settings, String mode) {
        this.minimumActionMode = mode != null ? mode.trim().toUpperCase(Locale.ROOT) : "OBSERVE";
        setMinimumActionSettings(settings);
    }

    /**
     * The v1.0 output block of the bundle's features, from the product prompt document: its output parts (the fields,
     * the meaning of every reason code with the lines it may cite, which line a difference code cites) for the short
     * output contract v5 (v1.0, K30); the output contract v4 block for a measured variant.
     */
    String buildDecisionSectionV1(SecurityPromptBuildContext context) {
        AssembledPrompt version = promptVersionOf(context != null ? context.getEvent() : null);
        List<PromptVersionDocument.Part> parts = version.drawnParts(SecurityDecisionPromptDocument.OUTPUT_GROUP,
                Set.of());
        return "\n" + AssembledPrompt.draw(parts, version.holding(Set.of()), (part, holding) ->
                SecurityDecisionPromptDocument.REASON_CODES_PART.equals(part.key())
                        ? SecurityDecisionPromptDocument.reasonCodeLines(part, SecurityDecisionOutputContractV4.citedLines())
                        : null);
    }

    /**
     * The conditions the v1.0 system text of the request is drawn under: an agent's request, and the minimum action
     * floors when the host enforces them (K32, decision D10) for a bundle that does not state them in its decision rules.
     */
    private Set<String> v1Conditions(SecurityPromptBuildContext context) {
        Set<String> conditions = new LinkedHashSet<>();
        if (agentRequest(context)) {
            conditions.add(SecurityDecisionPromptDocument.AGENT_REQUEST);
        }
        if (minimumActionEnforced()) {
            conditions.add(SecurityDecisionPromptDocument.MINIMUM_ACTION_ENFORCE);
        }
        return conditions;
    }

    /** Whether the host enforces the minimum action floors and turned at least one on. */
    private boolean minimumActionEnforced() {
        MinimumActionRules.Settings rules = minimumActionSettings;
        return "ENFORCE".equalsIgnoreCase(minimumActionMode)
                && (rules.identityEnabled() || rules.newDeviceExportEnabled() || rules.policySatisfactionEnabled());
    }

    /**
     * The v1.0 system text, from the version the event runs (plan 6-1, 6-2): its judgment parts in order, the parts it
     * includes, and the minimum action floors when the host enforces them (K32).
     */
    String buildSystemInstructionV1(SecurityPromptBuildContext context) {
        AssembledPrompt version = promptVersionOf(context != null ? context.getEvent() : null);
        Set<String> conditions = v1Conditions(context);
        return version.draw(AssembledPrompt.JUDGMENT, conditions, (part, holding) ->
                SecurityDecisionPromptDocument.MINIMUM_ACTION_PART.equals(part.key())
                        ? SecurityDecisionPromptDocument.minimumActionRules(part, minimumActionSettings) : null);
    }

    /** The system sections: the judgment text and the output parts of the version. */
    private static final List<PromptSectionPlan> SYSTEM_SECTION_PLANS = List.of(
            new PromptSectionPlan(SecurityPromptSectionCatalog.SYSTEM_INSTRUCTION, PromptSectionPriorityClass.P0_REQUIRED, false, false,
                    (template, context) -> template.buildSystemInstructionV1(context)),
            new PromptSectionPlan(SecurityPromptSectionCatalog.DECISION_CONTRACT, PromptSectionPriorityClass.P0_REQUIRED, false, false,
                    (template, context) -> template.buildDecisionSectionV1(context)));

    /** The dictionary a version draws its user prompt with: its renderer, entries, slot plans and layout name. */
    record DictionaryKit(PromptDictionaryRenderer renderer, List<PromptDictionaryEntry> entries,
                         PromptDictionarySlotPlanProvider slotPlans, String layoutName) {
    }

    /** The dictionary of the bundle; a v1.0 version with the decision rules states their conclusion lines (D6). */
    private DictionaryKit dictionaryKit(AssembledPrompt version) {
        return SecurityDecisionVersionFeatures.of(version).conclusionLines()
                ? new DictionaryKit(v1RulesDictionaryRenderer, SecurityDecisionPromptDictionary.V1_RULES_ENTRIES,
                v1RulesDictionarySlotPlans, USER_PROMPT_LAYOUT_V1)
                : new DictionaryKit(v1DictionaryRenderer, SecurityDecisionPromptDictionary.V1_ENTRIES,
                v1DictionarySlotPlans, USER_PROMPT_LAYOUT_V1);
    }

    String buildUserProfileNarrative(SecurityEvent event, DetectedPatterns patterns,
            BehaviorAnalysis behaviorAnalysis, BaselineStatus baselineStatus) {
        return buildUserProfileNarrative(event, patterns, behaviorAnalysis, baselineStatus, true);
    }

    String buildUserProfileNarrative(SecurityEvent event, DetectedPatterns patterns,
            BehaviorAnalysis behaviorAnalysis, BaselineStatus baselineStatus,
            boolean includeWorkProfileEvidenceState) {
        StringBuilder section = new StringBuilder();
        LearningContextEvidence learningEvidence = behaviorAnalysis != null
                ? behaviorAnalysis.getLearningContextEvidence()
                : null;
        ObservedPatternSnapshot observedPatterns = learningEvidence != null
                ? learningEvidence.observedPatterns()
                : null;
        List<CurrentVsObservedDeltaSnapshot> currentVsObservedDeltas = learningEvidence != null
                ? learningEvidence.currentVsObservedDeltas()
                : List.of();
        section.append("\n=== USER PROFILE ===\n");

        Map<String, Object> meta = event != null ? event.getMetadata() : null;
        if (meta != null) {
            Object userRoles = meta.get("userRoles");
            if (userRoles != null) {
                section.append("UserRoles: ").append(userRoles).append("\n");
            }
        }

        boolean newUserBaseline = baselineStatus == BaselineStatus.NEW_USER;
        if (newUserBaseline) {
            section.append("BaselineProfileStatus: NEW_USER\n");
            section.append("PersonalBaselineStatus: NOT_ESTABLISHED\n");
            section.append("BaselineSupportSummary: No verified personal behavioral history is available yet.\n");
        }

        boolean sparsePersonalHistory = baselineStatus == BaselineStatus.SPARSE_PERSONAL_HISTORY;
        if (sparsePersonalHistory) {
            section.append("BaselineProfileStatus: SPARSE_PERSONAL_HISTORY\n");
            section.append("PersonalBaselineStatus: NOT_ESTABLISHED\n");
            section.append("BaselineSupportSummary: Personal history is still sparse; shared reference evidence is not the same as an established personal norm.\n");
        }

        if (baselineStatus != BaselineStatus.ESTABLISHED
                && baselineStatus != BaselineStatus.PROVISIONAL
                && !sparsePersonalHistory
                && !newUserBaseline) {
            section.append("BaselineProfileStatus: ").append(baselineStatus != null ? baselineStatus.name() : "UNAVAILABLE").append("\n");
            section.append("BaselineSupportSummary: User profile evidence is limited or unavailable.\n");
            return section.toString();
        }

        boolean establishedPersonalBaseline = baselineStatus == BaselineStatus.ESTABLISHED;
        if (!sparsePersonalHistory && !newUserBaseline) {
            section.append("BaselineProfileStatus: ")
                    .append(establishedPersonalBaseline ? "ESTABLISHED" : "PROVISIONAL")
                    .append("\n");
            section.append("PersonalBaselineStatus: ")
                    .append(establishedPersonalBaseline ? "ESTABLISHED" : "LEARNING_IN_PROGRESS")
                    .append("\n");
        }
        if (includeWorkProfileEvidenceState) {
            appendCompactFact(section, "WorkProfileEvidenceState",
                    resolveWorkProfileEvidenceState(baselineStatus, learningEvidence), 48);
        }
        appendCompactFact(section, "ObservedPatternEvidenceScope",
                learningEvidence != null ? learningEvidence.observedPatternEvidenceScope() : null, 64);
        CurrentRequestSnapshot requestSnapshot = buildCurrentRequestSnapshot(event, behaviorAnalysis, null);
        String currentAccessHour = requestSnapshot.currentAccessHour();
        String currentDayOfWeek = requestSnapshot.dayOfWeek();
        String currentNetwork = requestSnapshot.ipBand();
        String currentBrowser = requestSnapshot.deviceBrowser();
        String currentOperatingSystem = requestSnapshot.deviceOs();
        String currentPathFamily = requestSnapshot.pathFamily();
        String currentAuthenticationType = requestSnapshot.authenticationType();
        String currentActionFamily = requestSnapshot.actionFamily();
        String currentResourceFamily = requestSnapshot.resourceFamily();

        appendObservedPresence(section, "CurrentAccessHour", currentAccessHour, observedValues(observedPatterns, patterns, "hours"), "CurrentAccessHourPresentInObservedHours", 80);
        appendObservedPresence(section, "CurrentDayOfWeek", currentDayOfWeek, observedValues(observedPatterns, patterns, "days"), "CurrentDayPresentInObservedDays", 80);
        appendObservedPresence(section, "CurrentNetwork", currentNetwork, observedValues(observedPatterns, patterns, "networks"), "CurrentNetworkPresentInObservedNetworks", 96,
                SecuritySemanticNormalizer::sameNetwork);
        appendObservedPresence(section, "CurrentBrowser", currentBrowser, observedValues(observedPatterns, patterns, "browsers"), "CurrentBrowserPresentInObservedBrowsers", 96);
        appendObservedPresence(section, "CurrentOperatingSystem", currentOperatingSystem, observedValues(observedPatterns, patterns, "operatingSystems"), "CurrentOperatingSystemPresentInObservedOperatingSystems", 96);
        appendDevicePresence(section, currentBrowser, currentOperatingSystem, observedPatterns, patterns);
        appendObservedPresence(section, "CurrentPathFamily", currentPathFamily, observedValues(observedPatterns, patterns, "paths"), "CurrentPathPresentInObservedPaths", 180);
        appendObservedPresence(section, "CurrentAuthenticationType", currentAuthenticationType, observedValues(observedPatterns, patterns, "authTypes"), "CurrentAuthenticationTypePresentInObservedAuthTypes", 96);
        appendObservedPresence(section, "CurrentActionFamily", currentActionFamily, observedValues(observedPatterns, patterns, "actionFamilies"), "CurrentActionFamilyPresentInObservedActions", 96);
        appendObservedPresence(section, "CurrentResourceFamily", currentResourceFamily, observedValues(observedPatterns, patterns, "resourceFamilies"), "CurrentResourceFamilyPresentInObservedResources", 120);

        List<String> carryMissingFacts = learningEvidence != null ? learningEvidence.carryMissingFacts() : List.of();
        List<String> missingObservedFacts = carryMissingFacts.stream()
                .filter(StringUtils::hasText)
                .filter(fact -> fact.startsWith("Observed"))
                .toList();
        boolean observedComparisonIncomplete = currentVsObservedDeltas.isEmpty() && !missingObservedFacts.isEmpty();
        section.append("CurrentVsObservedDeltaCount: ")
                .append(observedComparisonIncomplete ? "UNKNOWN" : currentVsObservedDeltas.size())
                .append("\n");
        appendCompactFact(section, "StrongestCurrentVsObservedDelta",
                observedComparisonIncomplete
                        ? "insufficient observed evidence"
                        : currentVsObservedDeltas.isEmpty()
                        ? "none"
                        : currentVsObservedDeltas.get(0).description(),
                120);
        appendCompactFact(section, "CurrentVsObservedDeltaSummary",
                observedComparisonIncomplete
                        ? "current-vs-observed comparison not reliable; missing observed dimensions: "
                        + summarizeExamples(missingObservedFacts, 4, 48)
                        : currentVsObservedDeltas.isEmpty()
                        ? "no direct current-vs-observed mismatch detected"
                        : summarizeExamples(currentVsObservedDeltas.stream().map(CurrentVsObservedDeltaSnapshot::description).toList(), 4, 72),
                180);
        boolean directCombinationEvidenceMissing = learningEvidence == null
                || learningEvidence.personalRetrievedEvidence().isEmpty();
        boolean supportingOnlyReferenceAvailable = learningEvidence != null
                && !learningEvidence.supportingRetrievedEvidence().isEmpty();
        section.append("CurrentRequestCombinationSeenCount: ")
                .append(directCombinationEvidenceMissing
                        ? "UNKNOWN"
                        : learningEvidence.currentRequestCombinationSeenCount())
                .append("\n");
        appendCompactFact(section, "CurrentRequestCombinationEvidenceScope",
                learningEvidence != null ? learningEvidence.currentRequestCombinationEvidenceScope() : null,
                80);
        appendCompactFact(section, "CurrentRequestCombinationComparedDimensions",
                learningEvidence != null ? learningEvidence.currentRequestCombinationComparedDimensions() : null,
                180);
        appendCompactFact(section, "CurrentRequestClosestObservedOverlap",
                directCombinationEvidenceMissing
                        ? null
                        : learningEvidence.currentRequestClosestObservedOverlap(),
                80);
        appendCompactFact(section, "StrongestCurrentRequestCombinationDelta",
                directCombinationEvidenceMissing
                        ? "no direct personal combination evidence"
                        : learningEvidence.strongestCurrentRequestCombinationDelta(),
                160);
        appendCompactFact(section, "CurrentRequestCombinationSummary",
                learningEvidence != null ? learningEvidence.currentRequestCombinationSummary() : null,
                200);
        appendCompactFact(section, "ObservedComparableCombination1",
                directCombinationEvidenceMissing
                        ? (supportingOnlyReferenceAvailable
                        ? "supporting-only reference available; no direct personal comparable combination evidence"
                        : "no direct personal comparable combination evidence")
                        : learningEvidence.representativeCombinationSummary(),
                220);

        appendCompactFact(section, "ObservedHours", joinValues(observedValues(observedPatterns, patterns, "hours")), 120);
        appendCompactFact(section, "ObservedDays", joinValues(observedValues(observedPatterns, patterns, "days")), 120);
        appendCompactFact(section, "ObservedNetworks", joinValues(observedValues(observedPatterns, patterns, "networks")), 160);
        appendCompactFact(section, "ObservedBrowsers", joinValues(observedValues(observedPatterns, patterns, "browsers")), 140);
        appendCompactFact(section, "ObservedOperatingSystems", joinValues(observedValues(observedPatterns, patterns, "operatingSystems")), 140);
        appendCompactFact(section, "ObservedDevices", joinValues(observedPatterns != null ? observedPatterns.devices() : List.of()), 180);
        appendCompactFact(section, "FrequentPaths", joinValues(observedValues(observedPatterns, patterns, "paths")), 180);
        appendCompactFact(section, "ObservedAuthenticationTypes", joinValues(observedValues(observedPatterns, patterns, "authTypes")), 120);
        appendCompactFact(section, "ObservedActionFamilies", joinValues(observedValues(observedPatterns, patterns, "actionFamilies")), 140);
        appendCompactFact(section, "ObservedResourceFamilies", joinValues(observedValues(observedPatterns, patterns, "resourceFamilies")), 160);

        if (behaviorAnalysis != null && behaviorAnalysis.getBaselineUpdateCount() != null) {
            section.append("BaselineObservations: ")
                    .append(behaviorAnalysis.getBaselineUpdateCount()).append("\n");
        }

        String baselineContextSummary = summarizeBaselineContext(behaviorAnalysis, learningEvidence);
        appendCompactFact(section, "BaselineContextSummary", baselineContextSummary, 220);

        return section.toString();
    }

    private String ragRelevance(SecurityEvent event, List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return PastRecordRelevance.NO_DOCUMENTS;
        }
        // The path template and the target decide it, as for the canonical reasoning and the sealed evidence (W2-8).
        return PastRecordRelevance.relevance(requestSubject(event), documents.stream()
                .filter(Objects::nonNull)
                .map(document -> PastRecordRelevance.Subject.ofRecord(document.getMetadata(), document.getText()))
                .toList());
    }

    private PastRecordRelevance.Subject requestSubject(SecurityEvent event) {
        return event == null
                ? PastRecordRelevance.Subject.ofRequest(null, null)
                : PastRecordRelevance.Subject.ofRequest(event.getMetadata(), event.getDescription());
    }

    String buildSupportingLearningContextSection(BehaviorAnalysis behaviorAnalysis) {
        LearningContextEvidence learningEvidence = behaviorAnalysis != null
                ? behaviorAnalysis.getLearningContextEvidence()
                : null;
        if (learningEvidence == null) {
            return null;
        }

        boolean supportingBaselineAvailable = learningEvidence.supportingBaseline() != null
                && learningEvidence.supportingBaseline().available();
        boolean supportingComparablesAvailable = !learningEvidence.supportingRetrievedEvidence().isEmpty();
        if (!supportingBaselineAvailable && !supportingComparablesAvailable) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        section.append("\n")
                .append(SecurityPromptSectionCatalog.HEADER_SUPPORTING_LEARNING_CONTEXT)
                .append("\n");
        section.append("SupportingEvidenceMode: REFERENCE_ONLY\n");
        section.append("SupportingEvidenceNeverReplacesPersonalBaseline: true\n");

        if (supportingBaselineAvailable) {
            BaselineEvidenceSnapshot supportingBaseline = learningEvidence.supportingBaseline();
            section.append("SupportingBaselineStatus: ")
                    .append(supportingBaseline.established() ? "AVAILABLE_REFERENCE" : "LIMITED_REFERENCE")
                    .append("\n");
            appendCompactFact(section, "SupportingBaselineSummary",
                    firstNonBlankText(
                            supportingBaseline.summary(),
                            "organization or cohort baseline is available as reference only"),
                    220);
        }

        section.append("SupportingComparableCount: ")
                .append(learningEvidence.supportingComparableCount())
                .append("\n");
        appendCompactFact(section, "SupportingComparableSummary",
                buildSupportingComparableSummary(learningEvidence), 360);

        RetrievedBehaviorEvidence representative = learningEvidence.representativeSupportingComparable(learningEvidence.strongestDelta());
        String supportingExample = renderComparableEvidence(representative);
        appendCompactFact(section, "SupportingComparableExample1", supportingExample, 320);
        appendCompactFact(section, "SupportingEvidenceConstraint",
                "Use supporting learning only as reference context, never as proof of an established personal norm.",
                220);
        return section.toString();
    }

    String buildThreatLearningSection(BehaviorAnalysis behaviorAnalysis) {
        StringBuilder section = new StringBuilder();
        appendIfPresent(section, buildDetectionStrategySection(behaviorAnalysis));

        String supportingThreatSection = buildThreatKnowledgePackSection(behaviorAnalysis);
        if (!hasPromptContent(supportingThreatSection)) {
            supportingThreatSection = buildThreatIntelligenceSection(behaviorAnalysis);
        }
        appendIfPresent(section, supportingThreatSection);

        String rendered = section.toString();
        return hasPromptContent(rendered) ? rendered : null;
    }

    /**
     * The v20 threat match (W3-6): the threat learning section without the outside feed's own words (the signal
     * summary, the knowledge case's campaign and explanation summaries), which the UNTRUSTED TEXT block carries instead.
     */
    String buildThreatLearningSectionWithoutOutsideText(BehaviorAnalysis behaviorAnalysis) {
        String section = buildThreatLearningSection(behaviorAnalysis);
        if (section == null) {
            return null;
        }
        String kept = Arrays.stream(section.split("\n", -1))
                .filter(line -> OUTSIDE_TEXT_LABELS.stream().noneMatch(label -> line.strip().startsWith(label + ":")))
                .collect(Collectors.joining("\n"));
        return hasPromptContent(kept) ? kept : null;
    }

    /**
     * The outside threat feed's own words for the match the threat learning section draws (W3-6): for a knowledge
     * pack, the first matched case's campaign summary (else its first two campaign facts) and explanation summary; for
     * the intelligence, the first matched signal's summary; else none. The texts are as written, cleaned only when
     * rendered as untrusted text.
     */
    List<String> outsideThreatKnowledgeTexts(BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return List.of();
        }
        if (hasPromptContent(buildThreatKnowledgePackSection(behaviorAnalysis))) {
            ThreatKnowledgePackMatchContext.MatchedKnowledgeCase matchedCase =
                    behaviorAnalysis.getThreatKnowledgePackMatchContext().matchedCases().get(0);
            if (matchedCase == null || matchedCase.knowledgeCase() == null) {
                return List.of();
            }
            ThreatKnowledgePackSnapshot.KnowledgeCaseItem knowledgeCase = matchedCase.knowledgeCase();
            List<String> texts = new ArrayList<>();
            String campaign = firstNonBlankText(knowledgeCase.campaignSummary(), joinFirstTexts(knowledgeCase.campaignFacts(), 2));
            if (campaign != null) {
                texts.add(campaign);
            }
            if (StringUtils.hasText(knowledgeCase.xaiSummary())) {
                texts.add(knowledgeCase.xaiSummary());
            }
            return texts;
        }
        ThreatIntelligenceMatchContext matchContext = behaviorAnalysis.getThreatIntelligenceMatchContext();
        if (matchContext == null || !matchContext.hasMatches() || matchContext.matchedSignals().isEmpty()) {
            return List.of();
        }
        ThreatIntelligenceMatchContext.MatchedSignal matched = matchContext.matchedSignals().get(0);
        return matched != null && matched.signal() != null && StringUtils.hasText(matched.signal().summary())
                ? List.of(matched.signal().summary())
                : List.of();
    }

    private static String joinFirstTexts(List<String> items, int maxItems) {
        if (items == null) {
            return null;
        }
        String joined = items.stream().filter(StringUtils::hasText).limit(maxItems).collect(Collectors.joining(" | "));
        return joined.isEmpty() ? null : joined;
    }

    /** The limit an untrusted text entry is cut to (W3-6): the request payload limit. */
    int untrustedTextLimit() {
        return tieredStrategyProperties.getTruncation().getLayer1().getPayload();
    }

    /** The request body as decoded for the prompt (W3-6), or null. */
    String decodedPayload(SecurityEvent event) {
        return event != null ? eventEnricher.getDecodedPayload(event).orElse(null) : null;
    }

    private String buildDetectionStrategySection(BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return null;
        }

        DetectionStrategyRuntimePack runtimePack = behaviorAnalysis.getDetectionStrategyRuntimePack();
        if (runtimePack == null || !runtimePack.runtimeReady() || runtimePack.strategies().isEmpty()) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        section.append("\n=== PROMOTED DETECTION STRATEGIES ===\n");
        section.append("PromotedDetectionStrategyCount: ").append(runtimePack.strategies().size()).append("\n");
        section.append("SupportingContextOnly: true (supporting context only)\n");

        int maxStrategies = Math.min(1, runtimePack.strategies().size());
        for (int i = 0; i < maxStrategies; i++) {
            DetectionStrategyRuntimePack.RuntimeStrategyItem item = runtimePack.strategies().get(i);
            if (item == null) {
                continue;
            }
            section.append(i + 1).append(". StrategyFamily: ")
                    .append(PromptTemplateUtils.sanitizeAndTruncate(item.strategyFamily(), 80))
                    .append(" | ConfidenceBand: ")
                    .append(PromptTemplateUtils.sanitizeAndTruncate(item.confidenceBand(), 40))
                    .append(" | Lift: ")
                    .append(String.format(Locale.ROOT, "%.2f", item.metadata().metrics().localLiftRate()))
                    .append("\n");

            appendCompactIndentedFact(section, "RequiredSignals",
                    summarizeList(item.requiredSignals(), 3, 120), 180);
            appendCompactIndentedFact(section, "RecommendedSignals",
                    summarizeList(item.recommendedSignals(), 3, 120), 180);
            appendCompactIndentedFact(section, "ApplicableContexts",
                    summarizeList(item.applicableContextClasses(), 2, 120), 180);
            appendCompactIndentedFact(section, "EvidenceSummary",
                    summarizeList(item.evidenceFacts(), 2, 160), 220);
            appendCompactIndentedFact(section, "PolicySummary",
                    summarizeList(item.policyFacts(), 2, 140), 200);
        }
        return section.toString();
    }

    private String buildThreatKnowledgePackSection(BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return null;
        }

        ThreatKnowledgePackMatchContext matchContext = behaviorAnalysis.getThreatKnowledgePackMatchContext();
        if (matchContext == null || !matchContext.hasMatches()) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        section.append("\n=== THREAT KNOWLEDGE PACK ===\n");
        section.append("ThreatKnowledgeMatchCount: ").append(matchContext.matchedCases().size()).append("\n");
        section.append("SupportingContextOnly: true (supporting context only)\n");

        int maxCases = Math.min(1, matchContext.matchedCases().size());
        for (int i = 0; i < maxCases; i++) {
            ThreatKnowledgePackMatchContext.MatchedKnowledgeCase matchedCase = matchContext.matchedCases().get(i);
            if (matchedCase == null || matchedCase.knowledgeCase() == null) {
                continue;
            }
            ThreatKnowledgePackSnapshot.KnowledgeCaseItem knowledgeCase = matchedCase.knowledgeCase();
            section.append(i + 1).append(". ThreatClass: ")
                    .append(PromptTemplateUtils.sanitizeAndTruncate(knowledgeCase.canonicalThreatClass(), 80))
                    .append(" | Region: ")
                    .append(PromptTemplateUtils.sanitizeAndTruncate(knowledgeCase.geoCountry(), 40))
                    .append(" | Tenants: ")
                    .append(knowledgeCase.affectedTenantCount())
                    .append(" | Observations: ")
                    .append(knowledgeCase.observationCount())
                    .append("\n");

            appendCompactIndentedFact(section, "ComparableEvidence",
                    summarizeList(matchedCase.matchedFacts(), 2, 180), 220);
            appendCompactIndentedFact(section, "CampaignSummary",
                    firstNonBlankText(
                            knowledgeCase.campaignSummary(),
                            summarizeList(knowledgeCase.campaignFacts(), 2, 160)),
                    220);
            appendCompactIndentedFact(section, "OutcomeSummary",
                    firstNonBlankText(
                            summarizeList(knowledgeCase.outcomeFacts(), 2, 160),
                            knowledgeCase.experimentStatus(),
                            summarizeList(knowledgeCase.experimentFacts(), 2, 160)),
                    220);
            appendCompactIndentedFact(section, "LearningSummary",
                    firstNonBlankText(
                            knowledgeCase.learningStatus(),
                            summarizeList(knowledgeCase.learningFacts(), 2, 160),
                            knowledgeCase.caseMemoryStatus(),
                            summarizeList(knowledgeCase.caseMemoryFacts(), 2, 160)),
                    220);
            appendCompactIndentedFact(section, "FalsePositiveCaution",
                    summarizeList(knowledgeCase.falsePositiveNotes(), 1, 180), 200);
            appendCompactIndentedFact(section, "XaiSummary", knowledgeCase.xaiSummary(), 220);
            appendCompactIndentedFact(section, "PromotionSummary",
                    firstNonBlankText(
                            knowledgeCase.promotionState(),
                            summarizeList(knowledgeCase.promotionFacts(), 2, 160)),
                    200);
        }
        return section.toString();
    }

    private String buildThreatIntelligenceSection(BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return null;
        }

        ThreatIntelligenceMatchContext matchContext = behaviorAnalysis.getThreatIntelligenceMatchContext();
        if (matchContext == null || !matchContext.hasMatches()) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        section.append("\n=== ACTIVE THREAT CAMPAIGN MATCHES ===\n");
        section.append("ThreatCampaignMatchCount: ").append(matchContext.matchedSignals().size()).append("\n");
        section.append("SupportingContextOnly: true (supporting context only)\n");

        int maxSignals = Math.min(1, matchContext.matchedSignals().size());
        for (int i = 0; i < maxSignals; i++) {
            ThreatIntelligenceMatchContext.MatchedSignal matchedSignal = matchContext.matchedSignals().get(i);
            if (matchedSignal == null || matchedSignal.signal() == null) {
                continue;
            }
            ThreatIntelligenceSnapshot.ThreatSignalItem signal = matchedSignal.signal();
            String threatClass = PromptTemplateUtils.sanitizeAndTruncate(signal.canonicalThreatClass(), 80);
            String geoCountry = PromptTemplateUtils.sanitizeAndTruncate(signal.geoCountry(), 40);
            String summary = PromptTemplateUtils.sanitizeAndTruncate(signal.summary(), 240);
            String tactics = signal.mitreTacticHints() == null || signal.mitreTacticHints().isEmpty()
                    ? null
                    : PromptTemplateUtils.sanitizeAndTruncate(String.join(", ", signal.mitreTacticHints()), 160);
            String targetSurfaces = signal.targetSurfaceHints() == null || signal.targetSurfaceHints().isEmpty()
                    ? null
                    : PromptTemplateUtils.sanitizeAndTruncate(String.join(", ", signal.targetSurfaceHints()), 160);
            String matchedFacts = matchedSignal.matchedFacts().isEmpty()
                    ? null
                    : PromptTemplateUtils.sanitizeAndTruncate(String.join(" ", matchedSignal.matchedFacts()), 320);

            section.append(i + 1).append(". ThreatClass: ").append(threatClass != null ? threatClass : "unknown");
            if (geoCountry != null) {
                section.append(" | Region: ").append(geoCountry);
            }
            section.append(" | Tenants: ").append(signal.affectedTenantCount());
            section.append(" | Observations: ").append(signal.observationCount());
            section.append("\n");

            if (targetSurfaces != null) {
                section.append("   TargetSurfaces: ").append(targetSurfaces).append("\n");
            }
            if (tactics != null) {
                section.append("   MitreTactics: ").append(tactics).append("\n");
            }
            if (signal.firstObservedAt() != null || signal.lastObservedAt() != null) {
                section.append("   ObservationWindow: ")
                        .append(signal.firstObservedAt() != null ? signal.firstObservedAt() : "unknown")
                        .append(" -> ")
                        .append(signal.lastObservedAt() != null ? signal.lastObservedAt() : "unknown")
                        .append("\n");
            }
            appendCompactIndentedFact(section, "RelevantFacts", matchedFacts, 220);
            appendCompactIndentedFact(section, "SignalSummary", summary, 220);
        }
        return section.toString();
    }

    String buildCohortBaselineSeedSection(BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null || !behaviorAnalysis.isCohortSeedApplied()) {
            return null;
        }

        BaselineSeedSnapshot seed = behaviorAnalysis.getCohortBaselineSeed();
        if (seed == null || !seed.featureEnabled() || !seed.seedAvailable()) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        section.append("\n=== COHORT BASELINE SEED (SUPPORTING CONTEXT ONLY) ===\n");
        section.append(ContextEvidenceGuidance.SEED_IS_SHARED_CONTEXT).append(' ');
        section.append(ContextEvidenceGuidance.SEED_DOES_NOT_OVERRIDE).append('\n');

        if (behaviorAnalysis.isOrganizationBaselineEstablished()) {
            section.append(ContextEvidenceGuidance.ORGANIZATION_BASELINE_FIRST).append(' ');
            section.append(ContextEvidenceGuidance.SEED_FOR_MISSING_DIMENSIONS).append('\n');
        } else {
            section.append("Tenant organization baseline is still immature. ");
            section.append(ContextEvidenceGuidance.SEED_AS_COLD_START_SUPPORT).append('\n');
        }

        if (!behaviorAnalysis.getCohortSeedSupportingDimensions().isEmpty()) {
            section.append("Use only for dimensions: ")
                    .append(String.join(", ", behaviorAnalysis.getCohortSeedSupportingDimensions()))
                    .append("\n");
        }
        if (behaviorAnalysis.getCohortSeedWeight() > 0.0d || StringUtils.hasText(behaviorAnalysis.getCohortSeedWeightState())) {
            section.append(String.format(Locale.ROOT, "Runtime weight: %.0f%%", behaviorAnalysis.getCohortSeedWeight() * 100.0d));
            if (StringUtils.hasText(behaviorAnalysis.getCohortSeedWeightState())) {
                section.append(" (")
                        .append(behaviorAnalysis.getCohortSeedWeightState())
                        .append(")");
            }
            section.append("\n");
        }
        for (String policyFact : behaviorAnalysis.getCohortSeedPolicyFacts().stream().limit(2).toList()) {
            section.append("Seed policy: ")
                    .append(PromptTemplateUtils.sanitizeAndTruncate(policyFact, 220))
                    .append("\n");
        }
        if (seed.cohortLabel() != null) {
            section.append("Cohort: ").append(PromptTemplateUtils.sanitizeAndTruncate(seed.cohortLabel(), 120)).append("\n");
        }
        if (seed.cohortTenantCount() > 0) {
            section.append("Cohort tenants: ").append(seed.cohortTenantCount()).append("\n");
        }
        if (seed.sampleUserBaselineCount() > 0L) {
            section.append("Sampled user baselines: ").append(seed.sampleUserBaselineCount()).append("\n");
        }
        if (!seed.topAccessHours().isEmpty()) {
            section.append("Typical cohort hours: ").append(joinIntegers(seed.topAccessHours())).append("\n");
        }
        if (!seed.topAccessDays().isEmpty()) {
            section.append("Typical cohort days: ").append(joinIntegers(seed.topAccessDays())).append("\n");
        }
        if (!seed.topOperatingSystems().isEmpty()) {
            section.append("Typical cohort operating systems: ")
                    .append(PromptTemplateUtils.sanitizeAndTruncate(String.join(", ", seed.topOperatingSystems()), 160))
                    .append("\n");
        }
        if (seed.snapshotDate() != null) {
            section.append("Snapshot date: ").append(seed.snapshotDate()).append("\n");
        }
        return section.toString();
    }

    DetectedPatterns collectDetectedPatterns(List<Document> relatedDocuments, String userId,
                                             PastRecordRelevance.Subject request) {
        DetectedPatterns patterns = new DetectedPatterns();
        StringBuilder relatedContextBuilder = new StringBuilder();

        int maxRagDocs = tieredStrategyProperties.getLayer1().getPrompt().getMaxRagDocuments();
        int rawExcerptLimit = Math.min(1, Math.max(1, maxRagDocs));
        int maxDocs = (relatedDocuments != null) ? Math.min(maxRagDocs, relatedDocuments.size()) : 0;
        int addedDocs = 0;
        int rawDocCount = 0;

        for (int i = 0; i < maxDocs && addedDocs < maxRagDocs; i++) {
            Document doc = relatedDocuments.get(i);

            Map<String, Object> docMetadata = doc.getMetadata();
            if (userId != null) {
                Object docUserId = docMetadata.get("userId");
                if (docUserId != null && !userId.equals(docUserId.toString())) {
                    continue;
                }
            }

            String content = doc.getText();
            if (content == null || content.isBlank()) {
                continue;
            }

            collectPatternFromDocument(docMetadata, patterns);
            if (rawDocCount < rawExcerptLimit) {
                if (!relatedContextBuilder.isEmpty()) {
                    relatedContextBuilder.append("\n");
                }

                String docMeta = buildDocumentMetadata(doc, addedDocs + 1, request);
                int maxLength = tieredStrategyProperties.getTruncation().getLayer1().getRagDocument();
                String truncatedContent = PromptTemplateUtils.truncate(content, maxLength);

                relatedContextBuilder.append(docMeta).append(" ").append(truncatedContent);
                rawDocCount++;
            }
            addedDocs++;
        }

        if (addedDocs > rawDocCount) {
            if (!relatedContextBuilder.isEmpty()) {
                relatedContextBuilder.append("\n");
            }
            relatedContextBuilder.append("[FUSED_SUMMARY] ")
                    .append(buildComparableSummary(null, patterns, addedDocs));
        }

        patterns.hasRelatedDocs = relatedContextBuilder.length() > 0;
        patterns.relatedContext = patterns.hasRelatedDocs ? relatedContextBuilder.toString() : null;

        return patterns;
    }

    private void collectPatternFromDocument(Map<String, Object> metadata, DetectedPatterns patterns) {
        Object userAgentOS = metadata.get("userAgentOS");
        if (userAgentOS != null && !userAgentOS.toString().isEmpty()) {
            patterns.osSet.add(userAgentOS.toString());
        }

        Object sourceIp = metadata.get("sourceIp");
        if (sourceIp != null && !sourceIp.toString().isEmpty()) {
            patterns.ipSet.add(SecurityEventEnricher.normalizeIP(sourceIp.toString()));
        }

        Object hour = metadata.get("hour");
        if (hour != null) {
            patterns.hourSet.add(hour.toString());
        }
        Object day = metadata.get("dayOfWeek");
        if (day != null) {
            patterns.daySet.add(day.toString());
        }

        Object userAgentBrowser = metadata.get("userAgentBrowser");
        if (userAgentBrowser != null && !userAgentBrowser.toString().isEmpty()) {
            patterns.uaSet.add(userAgentBrowser.toString());
        }

        Object requestPath = metadata.get("requestPath");
        if (requestPath != null && !requestPath.toString().isEmpty()) {
            String pathStr = requestPath.toString();
            int secondSlash = pathStr.indexOf('/', 1);
            int thirdSlash = secondSlash > 0 ? pathStr.indexOf('/', secondSlash + 1) : -1;
            if (thirdSlash > 0) {
                patterns.pathSet.add(pathStr.substring(0, thirdSlash) + "/*");
            } else {
                patterns.pathSet.add(pathStr);
            }
        }
    }

    void enrichPatternsFromBaseline(DetectedPatterns patterns, BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return;
        }

        addAllNonEmpty(patterns.ipSet, behaviorAnalysis.getBaselineIpRanges());
        addAllNonEmpty(patterns.osSet, behaviorAnalysis.getBaselineOperatingSystems());
        addAllNonEmpty(patterns.uaSet, behaviorAnalysis.getBaselineUserAgents());
        addAllNonEmpty(patterns.pathSet, behaviorAnalysis.getBaselineFrequentPaths());

        if (behaviorAnalysis.getBaselineAccessHours() != null) {
            for (Integer hour : behaviorAnalysis.getBaselineAccessHours()) {
                if (hour != null) {
                    patterns.hourSet.add(hour.toString());
                }
            }
        }
        if (behaviorAnalysis.getBaselineAccessDays() != null) {
            for (Integer day : behaviorAnalysis.getBaselineAccessDays()) {
                if (day != null) {
                    patterns.daySet.add(day.toString());
                }
            }
        }
    }

    private void addAllNonEmpty(Set<String> target, String[] source) {
        if (source == null) {
            return;
        }
        for (String value : source) {
            if (value != null && !value.isEmpty()) {
                target.add(value);
            }
        }
    }

    private String buildDocumentMetadata(Document doc, int docIndex, PastRecordRelevance.Subject request) {
        return "[Doc" + docIndex + documentMetadataBody(doc, request) + "]";
    }

    /** The metadata of a past record document as {@code |type=…|user=…}, without the brackets and number. */
    private String documentMetadataBody(Document doc, PastRecordRelevance.Subject request) {
        StringBuilder meta = new StringBuilder();

        Map<String, Object> metadata = doc.getMetadata();
        Object typeObj = metadata.get(VectorDocumentMetadata.DOCUMENT_TYPE);
        if (typeObj == null) {
            typeObj = metadata.get(VectorDocumentMetadata.SOURCE_TYPE);
        }
        if (typeObj == null) {
            typeObj = metadata.get("type");
        }
        if (typeObj != null) {
            meta.append("|type=").append(typeObj.toString());
        }

        Object userId = metadata.get(VectorDocumentMetadata.USER_ID);
        if (userId != null) {
            meta.append("|user=").append(userId);
        }

        Object sourceIp = metadata.get("sourceIp");
        if (sourceIp != null) {
            meta.append("|ip=").append(sourceIp);
        }

        Object hour = metadata.get("hour");
        if (hour != null) {
            meta.append("|hour=").append(hour);
        } else {
            Object timestamp = metadata.get(VectorDocumentMetadata.TIMESTAMP);
            if (timestamp != null) {
                String timeStr = timestamp.toString();
                if (timeStr.contains("T") && timeStr.length() > 13) {
                    meta.append("|hour=").append(timeStr.substring(11, 13));
                }
            }
        }

        Object requestUri = metadata.get("requestPath");
        if (requestUri != null) {
            meta.append("|path=").append(requestUri);
        }
        String documentPathFamily = firstNonBlankText(
                metadata.get("pathFamily"),
                metadata.get("requestPathFamily"),
                SecuritySemanticNormalizer.normalizePathFamily(requestUri != null ? requestUri.toString() : null),
                SecuritySemanticNormalizer.normalizePathFamily(extractPathToken(doc.getText())));
        appendDocumentTraceValue(meta, "pathFamily", documentPathFamily, 120);
        if (request != null) {
            // Whether the record acted on the request's target (W2-8): the path template's values, not the method.
            appendDocumentTraceValue(meta, "sameTarget", PastRecordRelevance.sameTarget(
                    request, PastRecordRelevance.Subject.ofRecord(metadata, doc.getText())), 8);
        }

        // A record's class is the class stored with it, else its sensitivity; never a family hint (W2-10).
        String documentResourceFamily = firstNonBlankText(
                metadata.get("resourceFamily"),
                SecuritySemanticNormalizer.normalizeResourceClass(
                        metadata.get("resourceSensitivity"), metadata.get("sensitivity")));
        appendDocumentTraceValue(meta, "resourceFamily", documentResourceFamily, 48);

        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.AUTHORIZATION_DECISION, "authorization", 48);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.ACCESS_SCOPE, "scope", 24);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.PURPOSE_MATCH, "purpose", 8);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.RETRIEVAL_PURPOSE, "retrievalPurpose", 48);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY, "retrievalPolicy", 120);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.ARTIFACT_ID, "artifact", 40);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.ARTIFACT_VERSION, "version", 16);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.TENANT_BOUND, "tenantBound", 8);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.PROMPT_SAFETY_DECISION, "guard", 36);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.MEMORY_READ_DECISION, "memory", 36);
        appendDocumentTrace(meta, metadata, VectorDocumentMetadata.PROVENANCE_SUMMARY, "prov", 56);

        return meta.toString();
    }

    /**
     * The canonical context the event's prompt is drawn with, instead of the one the provider would resolve now: a
     * sealed decision drawn again (a replay) is drawn with the context it was sealed with.
     */
    public void useCanonicalContext(SecurityEvent event, CanonicalSecurityContext context) {
        if (event == null || !StringUtils.hasText(event.getEventId()) || context == null) {
            return;
        }
        byte[] snapshot = snapshotCanonicalContext(context);
        if (snapshot.length > 0) {
            pinnedCanonicalContexts.put(event.getEventId(), snapshot);
        }
    }

    Optional<CanonicalSecurityContext> resolveCanonicalSecurityContext(SecurityEvent event) {
        byte[] pinned = event != null && StringUtils.hasText(event.getEventId())
                ? pinnedCanonicalContexts.getIfPresent(event.getEventId()) : null;
        if (pinned != null) {
            return restoreCanonicalContext(pinned);
        }
        if (event == null || canonicalSecurityContextProvider == null) {
            return Optional.empty();
        }
        String cacheKey = canonicalContextCacheKey(event);
        byte[] cached = canonicalSecurityContextCache.getIfPresent(cacheKey);
        if (cached != null) {
            Optional<CanonicalSecurityContext> restored = restoreCanonicalContext(cached);
            if (restored.isPresent()) {
                return restored;
            }
            canonicalSecurityContextCache.invalidate(cacheKey);
        }
        Optional<CanonicalSecurityContext> resolved = canonicalSecurityContextProvider.resolve(event);
        resolved.ifPresent(context -> cacheCanonicalSecurityContext(event, context));
        return resolved.flatMap(context -> restoreCanonicalContext(snapshotCanonicalContext(context)))
                .or(() -> resolved);
    }

    /**
     * PR-91: the limit of the canonical contexts kept for a maximum heap of {@code maxHeapBytes}: a thirty-second of it,
     * between 8 MiB and 128 MiB. A 384 MiB heap gives 12 MiB, 512 MiB 16 MiB, 2 GiB 64 MiB, 4 GiB or more 128 MiB.
     */
    static long defaultCanonicalContextBudgetBytes(long maxHeapBytes) {
        return Math.max(MIN_CANONICAL_CONTEXT_BYTES,
                Math.min(MAX_CANONICAL_CONTEXT_BYTES, maxHeapBytes / CANONICAL_CONTEXT_HEAP_SHARE_DIVISOR));
    }

    /** The bytes of the canonical contexts kept (PR-91). */
    long canonicalContextCacheBytes() {
        canonicalSecurityContextCache.cleanUp();
        return canonicalSecurityContextCache.asMap().values().stream().mapToLong(snapshot -> snapshot.length).sum();
    }

    void clearCanonicalContextCache() {
        canonicalSecurityContextCache.invalidateAll();
    }

    private void cacheCanonicalSecurityContext(SecurityEvent event, CanonicalSecurityContext context) {
        if (event == null || context == null) {
            return;
        }
        byte[] snapshot = snapshotCanonicalContext(context);
        if (snapshot.length > 0) {
            canonicalSecurityContextCache.put(canonicalContextCacheKey(event), snapshot);
        }
    }

    private String canonicalContextCacheKey(SecurityEvent event) {
        Map<String, Object> input = new TreeMap<>();
        input.put("userId", event.getUserId());
        input.put("sessionId", event.getSessionId());
        input.put("sourceIp", event.getSourceIp());
        input.put("description", event.getDescription());
        input.put("metadata", event.getMetadata() == null ? Map.of() : new TreeMap<>(event.getMetadata()));
        String inputText;
        try {
            inputText = canonicalContextSnapshotMapper.writeValueAsString(input);
        }
        catch (JsonProcessingException exception) {
            inputText = input.toString();
        }
        Map<String, Object> metadata = event.getMetadata() == null ? Map.of() : event.getMetadata();
        String revision = firstCacheText(
                metadata.get("evidenceRevision"),
                metadata.get("revisionNo"),
                metadata.get("sealedEvidence.revision"),
                "UNREVISIONED");
        String contractVersion = firstCacheText(
                metadata.get("contractVersion"),
                defaultDescriptor.contractVersion(),
                "UNVERSIONED");
        return firstCacheText(event.getEventId(), "NO_EVENT_ID")
                + '\u001f' + revision
                + '\u001f' + contractVersion
                + '\u001f' + PromptGovernanceSupport.sha256(inputText);
    }

    private byte[] snapshotCanonicalContext(CanonicalSecurityContext context) {
        if (context == null) {
            return new byte[0];
        }
        try {
            return canonicalContextSnapshotMapper.writeValueAsBytes(context);
        }
        catch (JsonProcessingException exception) {
            return new byte[0];
        }
    }

    private Optional<CanonicalSecurityContext> restoreCanonicalContext(byte[] snapshot) {
        if (snapshot == null || snapshot.length == 0) {
            return Optional.empty();
        }
        try {
            return Optional.of(canonicalContextSnapshotMapper.readValue(snapshot, CanonicalSecurityContext.class));
        }
        catch (Exception exception) {
            return Optional.empty();
        }
    }

    private String firstCacheText(Object... values) {
        if (values != null) {
            for (Object value : values) {
                if (value != null && !String.valueOf(value).isBlank()) {
                    return String.valueOf(value).trim();
                }
            }
        }
        return "";
    }

    String buildDelegatedObjectiveContextSection(CanonicalSecurityContext canonicalSecurityContext) {
        if (canonicalSecurityContext == null || promptContextComposer == null) {
            return null;
        }
        return promptContextComposer.composeDelegationSection(canonicalSecurityContext);
    }

    String buildReasoningMemoryContextSection(CanonicalSecurityContext canonicalSecurityContext) {
        if (canonicalSecurityContext == null || promptContextComposer == null) {
            return null;
        }
        return promptContextComposer.composeReasoningMemorySection(canonicalSecurityContext);
    }

    private void appendCompactFact(StringBuilder section, String label, String value, int maxLength) {
        String normalized = sanitizeSingleLine(value, maxLength);
        if (!StringUtils.hasText(normalized)) {
            return;
        }
        section.append(label).append(": ").append(normalized).append("\n");
    }

    private void appendCompactIndentedFact(StringBuilder section, String label, String value, int maxLength) {
        String normalized = sanitizeSingleLine(value, maxLength);
        if (!StringUtils.hasText(normalized)) {
            return;
        }
        section.append("   ").append(label).append(": ").append(normalized).append("\n");
    }

    private String sanitizeSingleLine(String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return PromptTemplateUtils.sanitizeAndTruncate(value.replace('\n', ' ').replace('\r', ' '), maxLength);
    }

    private String summarizeBaselineContext(BehaviorAnalysis behaviorAnalysis, LearningContextEvidence learningEvidence) {
        if (learningEvidence != null && learningEvidence.personalBaseline() != null) {
            String typedSummary = learningEvidence.personalBaseline().renderSummaryOrDiagnostic();
            if (StringUtils.hasText(typedSummary)) {
                return sanitizeSingleLine(typedSummary, 220);
            }
        }
        return null;
    }

    private String summarizeExamples(List<String> values, int maxItems, int maxLength) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.stream()
                .filter(StringUtils::hasText)
                .limit(Math.max(1, maxItems))
                .map(value -> PromptTemplateUtils.sanitizeAndTruncate(value, maxLength))
                .reduce((left, right) -> left + " | " + right)
                .orElse(null);
    }

    private String renderComparableEvidence(RetrievedBehaviorEvidence evidence) {
        if (evidence == null) {
            return null;
        }
        List<String> facts = new ArrayList<>();
        addSummaryFact(facts, "Path", firstNonBlankText(evidence.pathFamily(), evidence.requestPath()));
        addSummaryFact(facts, "Hour", evidence.accessHour());
        addSummaryFact(facts, "Day", evidence.accessDay());
        addSummaryFact(facts, "Network", firstNonBlankText(evidence.ipBand(), evidence.sourceIp()));
        addSummaryFact(facts, "Browser", evidence.browser());
        addSummaryFact(facts, "OperatingSystem", evidence.operatingSystem());
        addSummaryFact(facts, "AuthType", evidence.authenticationType());
        addSummaryFact(facts, "ActionFamily", evidence.actionFamily());
        addSummaryFact(facts, "ResourceFamily", evidence.resourceFamily());
        addSummaryFact(facts, "ResourceSensitivity", evidence.resourceSensitivity());
        if (facts.isEmpty()) {
            addSummaryFact(facts, "EvidenceText", scrubComparableEvidenceSummary(evidence.summary()));
        }
        return sanitizeSingleLine(String.join(" | ", facts), 420);
    }

    private String scrubComparableEvidenceSummary(String summary) {
        String normalized = sanitizeSingleLine(summary, 360);
        if (!StringUtils.hasText(normalized)) {
            return null;
        }
        normalized = normalized.replaceAll("(?i)\\bDecision\\s*:\\s*.*$", "").trim();
        normalized = normalized.replaceAll("(?i)\\b(?:proposedAction|autonomousAction|finalAction|decisionAction)\\s*=\\s*[^\\s|,;]+", "").trim();
        normalized = normalized.replaceAll("\\s{2,}", " ").trim();
        return StringUtils.hasText(normalized) ? normalized : null;
    }

    private String buildComparableSummary(LearningContextEvidence learningEvidence, DetectedPatterns patterns, int comparableCount) {
        List<String> facts = new ArrayList<>();
        if (comparableCount > 0) {
            facts.add("Records=" + comparableCount);
            facts.add("Source=PERSONAL_RETRIEVED_SUBSET");
        } else {
            facts.add("Records=0");
            facts.add("NoDirectPersonalComparableEvidence");
        }
        if (learningEvidence != null && !learningEvidence.personalRetrievedEvidence().isEmpty()) {
            addSummaryFact(facts, "Paths", summarizeComparableField(
                    learningEvidence.personalRetrievedEvidence().stream()
                            .map(evidence -> firstNonBlankText(evidence.pathFamily(), evidence.requestPath()))
                            .toList()));
            addSummaryFact(facts, "Hours", summarizeComparableField(
                    learningEvidence.personalRetrievedEvidence().stream()
                            .map(RetrievedBehaviorEvidence::accessHour)
                            .toList()));
            addSummaryFact(facts, "Days", summarizeComparableField(
                    learningEvidence.personalRetrievedEvidence().stream()
                            .map(RetrievedBehaviorEvidence::accessDay)
                            .toList()));
            addSummaryFact(facts, "Networks", summarizeComparableField(
                    learningEvidence.personalRetrievedEvidence().stream()
                            .map(evidence -> firstNonBlankText(evidence.ipBand(), evidence.sourceIp()))
                            .toList()));
            addSummaryFact(facts, "Browsers", summarizeComparableField(
                    learningEvidence.personalRetrievedEvidence().stream()
                            .map(RetrievedBehaviorEvidence::browser)
                            .toList()));
            addSummaryFact(facts, "OperatingSystems", summarizeComparableField(
                    learningEvidence.personalRetrievedEvidence().stream()
                            .map(RetrievedBehaviorEvidence::operatingSystem)
                            .toList()));
            addSummaryFact(facts, "AuthTypes", summarizeComparableField(
                    learningEvidence.personalRetrievedEvidence().stream()
                            .map(RetrievedBehaviorEvidence::authenticationType)
                            .toList()));
            addSummaryFact(facts, "ActionFamilies", summarizeComparableField(
                    learningEvidence.personalRetrievedEvidence().stream()
                            .map(RetrievedBehaviorEvidence::actionFamily)
                            .toList()));
            addSummaryFact(facts, "ResourceFamilies", summarizeComparableField(
                    learningEvidence.personalRetrievedEvidence().stream()
                            .map(RetrievedBehaviorEvidence::resourceFamily)
                            .toList()));
        }
        return facts.isEmpty() ? null : sanitizeSingleLine(String.join(" | ", facts), 720);
    }

    private String summarizeComparableField(List<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .limit(6)
                .collect(Collectors.joining(", "));
    }

    private String buildSupportingComparableSummary(LearningContextEvidence learningEvidence) {
        if (learningEvidence == null || learningEvidence.supportingRetrievedEvidence().isEmpty()) {
            return "no supporting comparable evidence retrieved";
        }
        List<String> facts = new ArrayList<>();
        facts.add("Records=" + learningEvidence.supportingComparableCount());
        RetrievedBehaviorEvidence representative = learningEvidence.representativeSupportingComparable(learningEvidence.strongestDelta());
        if (representative != null) {
            addSummaryFact(facts, "Path", firstNonBlankText(representative.pathFamily(), representative.requestPath()));
            addSummaryFact(facts, "Hour", representative.accessHour());
            addSummaryFact(facts, "Day", representative.accessDay());
            addSummaryFact(facts, "Network", firstNonBlankText(representative.ipBand(), representative.sourceIp()));
            addSummaryFact(facts, "Browser", representative.browser());
            addSummaryFact(facts, "OperatingSystem", representative.operatingSystem());
            addSummaryFact(facts, "AuthType", representative.authenticationType());
            addSummaryFact(facts, "ActionFamily", representative.actionFamily());
            addSummaryFact(facts, "ResourceFamily", representative.resourceFamily());
        }
        return sanitizeSingleLine(String.join(" | ", facts), 360);
    }

    private void appendObservedPresence(
            StringBuilder section,
            String label,
            String currentValue,
            List<String> observedValues,
            String presenceLabel,
            int maxLength) {
        appendObservedPresence(section, label, currentValue, observedValues, presenceLabel, maxLength,
                String::equalsIgnoreCase);
    }

    private void appendObservedPresence(
            StringBuilder section,
            String label,
            String currentValue,
            List<String> observedValues,
            String presenceLabel,
            int maxLength,
            BiPredicate<String, String> sameValue) {
        if (!StringUtils.hasText(currentValue)) {
            String unavailable = "UNKNOWN - current value unavailable; do not infer baseline membership";
            appendCompactFact(section, label, unavailable, maxLength);
            section.append(presenceLabel)
                    .append(": ")
                    .append(unavailable)
                    .append("\n");
            return;
        }
        appendCompactFact(section, label, currentValue, maxLength);
        if (observedValues == null || observedValues.isEmpty()) {
            section.append(presenceLabel)
                    .append(": UNKNOWN\n");
            return;
        }
        section.append(presenceLabel)
                .append(": ")
                .append(observedValues.stream().anyMatch(value -> value != null && sameValue.test(value, currentValue)))
                .append("\n");
    }

    /**
     * The device as one dimension (W2-4): the browser on the operating system, compared by the rule of the learning
     * evidence, so the line agrees with the device delta and with NewDevice.
     */
    private void appendDevicePresence(
            StringBuilder section,
            String currentBrowser,
            String currentOperatingSystem,
            ObservedPatternSnapshot observedPatterns,
            DetectedPatterns fallbackPatterns) {
        String device = SecuritySemanticNormalizer.device(currentBrowser, currentOperatingSystem);
        if (!StringUtils.hasText(device)) {
            String unavailable = "UNKNOWN - current value unavailable; do not infer baseline membership";
            appendCompactFact(section, "CurrentDevice", unavailable, 120);
            section.append("CurrentDevicePresentInObservedDevices: ").append(unavailable).append("\n");
            return;
        }
        appendCompactFact(section, "CurrentDevice", device, 120);
        Boolean held = ObservedPatternSnapshot.holdsDevice(
                observedPatterns != null ? observedPatterns.devices() : List.of(),
                observedValues(observedPatterns, fallbackPatterns, "browsers"),
                observedValues(observedPatterns, fallbackPatterns, "operatingSystems"),
                currentBrowser,
                currentOperatingSystem);
        section.append("CurrentDevicePresentInObservedDevices: ")
                .append(held == null ? "UNKNOWN" : held)
                .append("\n");
    }

    private List<String> observedValues(ObservedPatternSnapshot observedPatterns, DetectedPatterns fallbackPatterns, String dimension) {
        if (observedPatterns != null) {
            return switch (dimension) {
                case "hours" -> observedPatterns.accessHours();
                case "days" -> observedPatterns.accessDays();
                case "networks" -> observedPatterns.networks();
                case "browsers" -> observedPatterns.browsers();
                case "operatingSystems" -> observedPatterns.operatingSystems();
                case "paths" -> observedPatterns.pathFamilies();
                case "authTypes" -> observedPatterns.authenticationTypes();
                case "actionFamilies" -> observedPatterns.actionFamilies();
                case "resourceFamilies" -> observedPatterns.resourceFamilies();
                default -> List.of();
            };
        }
        if (fallbackPatterns == null) {
            return List.of();
        }
        return switch (dimension) {
            case "hours" -> sortedValues(fallbackPatterns.hourSet);
            case "days" -> sortedValues(fallbackPatterns.daySet);
            case "networks" -> sortedValues(normalizeIPSet(fallbackPatterns.ipSet));
            case "browsers" -> sortedValues(fallbackPatterns.uaSet);
            case "operatingSystems" -> sortedValues(fallbackPatterns.osSet.stream()
                    .map(SecuritySemanticNormalizer::normalizeOperatingSystem)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toCollection(LinkedHashSet::new)));
            case "paths" -> sortedValues(fallbackPatterns.pathSet);
            default -> List.of();
        };
    }

    private List<String> sortedValues(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .filter(StringUtils::hasText)
                .sorted()
                .toList();
    }

    private String joinValues(List<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .collect(Collectors.joining(", "));
    }

    private void addSummaryFact(List<String> facts, String label, String value) {
        if (StringUtils.hasText(value)) {
            facts.add(label + "=" + value);
        }
    }

    private String summarizeList(List<String> items, int maxItems, int maxLength) {
        if (items == null || items.isEmpty()) {
            return null;
        }
        return items.stream()
                .filter(StringUtils::hasText)
                .limit(Math.max(1, maxItems))
                .map(item -> PromptTemplateUtils.sanitizeAndTruncate(item, maxLength))
                .reduce((left, right) -> left + " | " + right)
                .orElse(null);
    }

    private void appendDocumentTrace(StringBuilder meta, Map<String, Object> metadata, String key, String label, int maxLength) {
        Object value = metadata.get(key);
        if (value == null) {
            return;
        }
        String text = value.toString();
        if (text.isBlank()) {
            return;
        }
        text = PromptTemplateUtils.truncate(text, maxLength);
        meta.append("|").append(label).append("=").append(text);
    }

    private void appendDocumentTraceValue(StringBuilder meta, String label, String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return;
        }
        String text = value.trim();
        text = PromptTemplateUtils.truncate(text, maxLength);
        meta.append("|").append(label).append("=").append(text);
    }

    private String extractPathToken(String text) {
        return PastRecordRelevance.pathToken(text);
    }
    private boolean isValidData(String value) {
        return PromptTemplateUtils.isValidData(value);
    }

    private Set<String> normalizeIPSet(Set<String> ipSet) {
        if (ipSet == null || ipSet.isEmpty()) {
            return ipSet;
        }

        Set<String> normalized = new LinkedHashSet<>();
        for (String ip : ipSet) {
            // One network form (W2-4): an address and a learned prefix both read as their /24 band.
            normalized.add(SecuritySemanticNormalizer.normalizeNetwork(null, SecurityEventEnricher.normalizeIP(ip)));
        }
        return normalized;
    }

    private Integer resolveCurrentAccessHour(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        if (event.getTimestamp() != null) {
            return event.getLocalTimestamp().getHour();
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            Object currentAccessHour = metadata.get("currentAccessHour");
            if (currentAccessHour instanceof Number number) {
                return number.intValue();
            }
            if (currentAccessHour != null) {
                try {
                    return Integer.parseInt(currentAccessHour.toString());
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return null;
    }

    private CurrentRequestSnapshot buildCurrentRequestSnapshot(
            SecurityEvent event,
            BehaviorAnalysis behaviorAnalysis,
            CanonicalSecurityContext canonicalSecurityContext) {
        LearningContextEvidence learningEvidence = behaviorAnalysis != null
                ? behaviorAnalysis.getLearningContextEvidence()
                : null;
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        String requestPath = extractRequestPath(event);
        return new CurrentRequestSnapshot(
                event != null && event.getTimestamp() != null
                        ? event.getLocalTimestamp().toString()
                        : null,
                learningEvidence != null && learningEvidence.current() != null
                        ? learningEvidence.current().accessHour()
                        : text(resolveCurrentAccessHour(event)),
                learningEvidence != null && learningEvidence.current() != null
                        ? learningEvidence.current().dayOfWeek()
                        : text(resolveCurrentDayOfWeek(event)),
                learningEvidence != null && learningEvidence.current() != null
                        ? learningEvidence.current().authenticationType()
                        : SecuritySemanticNormalizer.normalizeAuthenticationType(
                        metadata != null ? metadata.get("authenticationType") : null,
                        metadata != null ? metadata.get("authMethod") : null),
                requestPath,
                learningEvidence != null && learningEvidence.current() != null
                        ? learningEvidence.current().pathFamily()
                        : currentPathFamily(canonicalSecurityContext, metadata, requestPath),
                learningEvidence != null && learningEvidence.current() != null
                        ? learningEvidence.current().actionFamily()
                        : currentActionFamily(canonicalSecurityContext, metadata),
                learningEvidence != null && learningEvidence.current() != null
                        ? learningEvidence.current().resourceFamily()
                        : currentResourceClass(canonicalSecurityContext, metadata),
                learningEvidence != null && learningEvidence.current() != null
                        ? learningEvidence.current().browser()
                        : resolveCurrentBrowser(event),
                learningEvidence != null && learningEvidence.current() != null
                        ? learningEvidence.current().operatingSystem()
                        : SecuritySemanticNormalizer.normalizeOperatingSystem(resolveCurrentOperatingSystem(event)),
                learningEvidence != null && learningEvidence.current() != null
                        ? learningEvidence.current().network()
                        : SecuritySemanticNormalizer.normalizeNetwork(
                        event != null ? event.getSourceIp() : null,
                        metadata != null ? firstNonBlankText(metadata.get("ipBand")) : null));
    }

    /**
     * The request's action family when no learning evidence carries it: the one the context resolved, else the one
     * the request's facts name, in the same order of sources.
     */
    private static String currentActionFamily(CanonicalSecurityContext context, Map<String, Object> metadata) {
        if (context != null && context.getResource() != null
                && StringUtils.hasText(context.getResource().getActionFamily())) {
            return ActionFamily.nameOrRaw(context.getResource().getActionFamily());
        }
        ActionFamily family = ActionFamilyResolver.resolve(metadata).family();
        return family != ActionFamily.UNKNOWN ? family.name() : null;
    }

    /**
     * The request's path family when no learning evidence carries it: the one the context resolved, else the host's
     * URL template or the generalized path, by the same rule.
     */
    private static String currentPathFamily(CanonicalSecurityContext context, Map<String, Object> metadata,
            String requestPath) {
        if (context != null && context.getResource() != null
                && StringUtils.hasText(context.getResource().getPathFamily())) {
            return context.getResource().getPathFamily();
        }
        return SecuritySemanticNormalizer.pathFamilyOf(metadata, requestPath);
    }

    /**
     * The request's class when no learning evidence carries it: the context's standard field, else the classification
     * values of the request. A family hint names a business category and never decides it (W2-10).
     */
    private static String currentResourceClass(CanonicalSecurityContext context, Map<String, Object> metadata) {
        if (context != null && context.getResource() != null) {
            String resourceClass = SecuritySemanticNormalizer.resourceClassOf(context.getResource());
            if (StringUtils.hasText(resourceClass)) {
                return resourceClass;
            }
        }
        return metadata == null ? null : SecuritySemanticNormalizer.normalizeResourceClass(
                metadata.get("resourceSensitivity"), metadata.get("sensitivity"), metadata.get("resourceType"));
    }

    private Integer resolveCurrentDayOfWeek(SecurityEvent event) {
        if (event == null || event.getTimestamp() == null) {
            return null;
        }
        return event.getLocalTimestamp().getDayOfWeek().getValue();
    }

    private String resolveCurrentBrowser(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            Object userAgentBrowser = metadata.get("userAgentBrowser");
            if (userAgentBrowser != null && !userAgentBrowser.toString().isBlank()) {
                return userAgentBrowser.toString();
            }
            Object deviceBrowser = metadata.get("deviceBrowser");
            Object deviceBrowserVersion = metadata.get("deviceBrowserVersion");
            if (deviceBrowser != null && !deviceBrowser.toString().isBlank()) {
                if (deviceBrowserVersion != null && !deviceBrowserVersion.toString().isBlank()) {
                    return deviceBrowser + "/" + deviceBrowserVersion;
                }
                return deviceBrowser.toString();
            }
        }
        return StringUtils.hasText(event.getUserAgent())
                ? SecurityEventEnricher.extractBrowserSignature(event.getUserAgent())
                : null;
    }

    private String resolveCurrentOperatingSystem(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            Object userAgentOS = metadata.get("userAgentOS");
            if (userAgentOS != null && !userAgentOS.toString().isBlank()) {
                return userAgentOS.toString();
            }
            Object deviceOs = metadata.get("deviceOs");
            if (deviceOs != null && !deviceOs.toString().isBlank()) {
                return deviceOs.toString();
            }
        }
        return StringUtils.hasText(event.getUserAgent())
                ? SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent())
                : null;
    }

    private String extractRequestPath(SecurityEvent event) {
        if (event == null) {
            return null;
        }

        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            Object path = metadata.get("requestPath");
            if (path != null && !path.toString().isEmpty()) {
                return path.toString();
            }

            Object uri = metadata.get("requestUri");
            if (uri != null && !uri.toString().isEmpty()) {
                return uri.toString();
            }
        }

        String desc = event.getDescription();
        if (desc != null && desc.contains(" /")) {
            int pathStart = desc.indexOf(" /") + 1;
            int pathEnd = desc.indexOf(" ", pathStart);
            if (pathEnd == -1) pathEnd = desc.length();
            String path = desc.substring(pathStart, pathEnd);
            if (!path.isEmpty()) {
                return path;
            }
        }

        return null;
    }

      BaselineStatus determineBaselineStatus(SecurityEvent event, BehaviorAnalysis behaviorAnalysis, LearningContextEvidence learningEvidence) {
        if (behaviorAnalysis == null && learningEvidence == null) {
            return BaselineStatus.ANALYSIS_UNAVAILABLE;
        }

        BaselineEvidenceSnapshot personalBaseline = learningEvidence != null ? learningEvidence.personalBaseline() : null;
        if (personalBaseline == null) {
            return behaviorAnalysis == null ? BaselineStatus.ANALYSIS_UNAVAILABLE : BaselineStatus.NOT_LOADED;
        }

        BaselineEvidenceStatus status = personalBaseline.status();
        if (status != null) {
            switch (status) {
                case SERVICE_UNAVAILABLE -> {
                    return BaselineStatus.SERVICE_UNAVAILABLE;
                }
                case MISSING_USER_ID -> {
                    return BaselineStatus.MISSING_USER_ID;
                }
                case ANALYSIS_UNAVAILABLE -> {
                    return BaselineStatus.ANALYSIS_UNAVAILABLE;
                }
                case AVAILABLE -> {
                    if (personalBaseline.established()) {
                        return BaselineStatus.ESTABLISHED;
                    }
                    if (personalBaseline.available() && personalBaseline.hasAnyObservedFacts()) {
                        return BaselineStatus.PROVISIONAL;
                    }
                }
                case NO_DATA -> {
                    boolean explicitNewUser = isExplicitNewUser(event);
                    boolean sparsePersonalHistory = hasSparsePersonalHistory(learningEvidence);
                    if (sparsePersonalHistory) {
                        return explicitNewUser ? BaselineStatus.NEW_USER : BaselineStatus.SPARSE_PERSONAL_HISTORY;
                    }
                    return explicitNewUser ? BaselineStatus.NEW_USER : BaselineStatus.NOT_LOADED;
                }
                default -> {
                }
            }
        }
        return BaselineStatus.NOT_LOADED;
    }

    private boolean hasSparsePersonalHistory(LearningContextEvidence learningEvidence) {
        if (learningEvidence == null) {
            return false;
        }

        boolean personalAvailable = learningEvidence.personalBaseline() != null
                && learningEvidence.personalBaseline().available();
        boolean personalComparableAvailable = !learningEvidence.personalRetrievedEvidence().isEmpty();
        boolean supportingAvailable = (learningEvidence.supportingBaseline() != null
                && learningEvidence.supportingBaseline().available())
                || !learningEvidence.supportingRetrievedEvidence().isEmpty();
        if (!personalAvailable && supportingAvailable) {
            return true;
        }
        if (personalAvailable) {
            return false;
        }
        if (personalComparableAvailable) {
            return true;
        }
        BaselineEvidenceSnapshot personalBaseline = learningEvidence.personalBaseline();
        if (personalBaseline != null) {
            return personalBaseline.status() == BaselineEvidenceStatus.NO_DATA;
        }
        return false;
    }

    private boolean isExplicitNewUser(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return false;
        }
        Object isNewUser = event.getMetadata().get("isNewUser");
        return Boolean.TRUE.equals(isNewUser);
    }

    private String firstNonBlankText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString();
            if (StringUtils.hasText(text)) {
                return text;
            }
        }
        return null;
    }

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    void appendIfPresent(StringBuilder sb, String section) {
        if (section != null) {
            sb.append(section);
        }
    }

    private record PromptSectionPlan(
            String sectionKey,
            PromptSectionPriorityClass priorityClass,
            boolean omittable,
            boolean trackAbsenceAsOmission,
            SecurityPromptSectionBuilder builder) {
    }

    /**
     * The past record retrieval state of one request (W3-2), and the state of an earlier search on the same request
     * that timed out before this one (N-MISS-1 D8), if there was one.
     */
    record RagState(boolean searchExecuted, String retrievalState, String absenceReason, String projectionState,
                    String applicability, String relevance, int relatedDocumentCount, boolean permissionFiltered,
                    int candidateCount, int authorizedCount, int deniedCount, String earlierRetrievalState) {

        RagState(boolean searchExecuted, String retrievalState, String absenceReason, String projectionState,
                 String applicability, String relevance, int relatedDocumentCount, boolean permissionFiltered,
                 int candidateCount, int authorizedCount, int deniedCount) {
            this(searchExecuted, retrievalState, absenceReason, projectionState, applicability, relevance,
                    relatedDocumentCount, permissionFiltered, candidateCount, authorizedCount, deniedCount, null);
        }

        /**
         * The state as the render keeps it with the prompt (execution metadata {@code promptRagState}), without the parts
         * it does not have (R1b-3: the one form the render writes and the prompt inspector reads back).
         */
        Map<String, Object> toMetadata() {
            Map<String, Object> state = new LinkedHashMap<>();
            state.put("searchExecuted", searchExecuted);
            state.put("retrievalState", retrievalState);
            state.put("absenceReason", absenceReason);
            state.put("projectionState", projectionState);
            state.put("applicability", applicability);
            state.put("relevance", relevance);
            state.put("relatedDocumentCount", relatedDocumentCount);
            state.put("permissionFiltered", permissionFiltered);
            state.put("candidateCount", candidateCount);
            state.put("authorizedCount", authorizedCount);
            state.put("deniedCount", deniedCount);
            state.put("earlierRetrievalState", earlierRetrievalState);
            state.values().removeIf(Objects::isNull);
            return Collections.unmodifiableMap(state);
        }

        /** The state read back from its metadata form; a part the form does not hold reads as nothing. */
        static RagState fromMetadata(Map<?, ?> state) {
            return new RagState(Boolean.TRUE.equals(state.get("searchExecuted")), text(state.get("retrievalState")),
                    text(state.get("absenceReason")), text(state.get("projectionState")),
                    text(state.get("applicability")), text(state.get("relevance")),
                    count(state.get("relatedDocumentCount")), Boolean.TRUE.equals(state.get("permissionFiltered")),
                    count(state.get("candidateCount")), count(state.get("authorizedCount")),
                    count(state.get("deniedCount")), text(state.get("earlierRetrievalState")));
        }

        private static String text(Object value) {
            return value != null ? value.toString() : null;
        }

        private static int count(Object value) {
            return value instanceof Number number ? number.intValue() : 0;
        }
    }

    /** W4-7: the facts a v20 prompt does not know, as its UNKNOWN block names them: the completeness reasons. */
    static final String PROMPT_EVIDENCE_COMPLETENESS_REASONS = "promptEvidenceCompletenessReasons";

    private record RenderedPromptSections(
            String composedText,
            List<String> renderedSectionKeys,
            List<PromptOmissionRecord> omissionLedger,
            Map<String, Long> sectionTimings,
            Map<String, Object> metadata) {
    }

    private record CachedRenderedPromptSections(
            String cacheKey,
            boolean cacheHit,
            RenderedPromptSections sections) {
    }

    boolean hasPromptContent(String section) {
        String normalized = normalizePromptSectionBody(section);
        return normalized != null && !normalized.isBlank();
    }

    private String normalizePromptSectionBody(String section) {
        if (section == null || section.isBlank()) {
            return null;
        }
        String normalized = section.stripLeading();
        if (normalized.startsWith("===")) {
            int newlineIndex = normalized.indexOf('\n');
            if (newlineIndex >= 0) {
                normalized = normalized.substring(newlineIndex + 1);
            } else {
                normalized = "";
            }
        }
        return normalized.strip();
    }

    private String joinIntegers(List<Integer> values) {
        List<String> normalized = new ArrayList<>();
        for (Integer value : values) {
            if (value != null) {
                normalized.add(String.valueOf(value));
            }
        }
        return String.join(", ", normalized);
    }

    private String resolveWorkProfileEvidenceState(
            BaselineStatus baselineStatus,
            LearningContextEvidence learningEvidence) {
        // The same state the work profile section states, from the one usual-behaviour view (W2-3, B-2).
        if (learningEvidence != null && learningEvidence.baselineView() != null
                && learningEvidence.baselineView().observed()) {
            return learningEvidence.baselineView().workProfileEvidenceState();
        }
        if (baselineStatus == BaselineStatus.ESTABLISHED) {
            return "TRUSTED";
        }
        if (baselineStatus == BaselineStatus.PROVISIONAL) {
            return "PROVISIONAL";
        }
        boolean hasAnyLearningEvidence = learningEvidence != null
                && (learningEvidence.personalBaseline() != null && learningEvidence.personalBaseline().available()
                || !learningEvidence.personalRetrievedEvidence().isEmpty()
                || !learningEvidence.supportingRetrievedEvidence().isEmpty());
        return hasAnyLearningEvidence ? "PROVISIONAL" : "INCOMPLETE";
    }

}


