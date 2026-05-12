package io.contexa.contexacore.std.components.prompt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.util.StringUtils;

public final class SafePromptNormalizationLLMViewComposer implements LLMViewComposer {

    private static final PromptTokenEstimatorRegistry PROMPT_TOKEN_ESTIMATOR_REGISTRY =
            PromptTokenEstimatorRegistry.defaultRegistry();
    private static final ThreadLocal<String> ESTIMATION_MODEL_HINT = new ThreadLocal<>();

    private static final String NORMALIZE_ONLY_MODE = "NORMALIZE_ONLY";
    private static final String NORMALIZE_AND_COMPACT_MODE = "NORMALIZE_AND_COMPACT";
    private static final String NORMALIZE_AND_FUSE_MODE = "NORMALIZE_AND_FUSE";

    private static final String SIMILAR_PAST_EVENTS_HEADER = "=== SIMILAR PAST EVENTS ===";
    private static final String CURRENT_REQUEST_HEADER = SecurityPromptSectionCatalog.HEADER_CURRENT_REQUEST_AND_EVENT;
    private static final String BRIDGE_RESOLUTION_HEADER = SecurityPromptSectionCatalog.HEADER_BRIDGE_RESOLUTION_CONTEXT;
    private static final String COVERAGE_HEADER = SecurityPromptSectionCatalog.HEADER_CONTEXT_COVERAGE;
    private static final String IDENTITY_ROLE_HEADER = SecurityPromptSectionCatalog.HEADER_IDENTITY_AND_ROLE_CONTEXT;
    private static final String AUTH_ASSURANCE_HEADER = SecurityPromptSectionCatalog.HEADER_AUTHENTICATION_AND_ASSURANCE_CONTEXT;
    private static final String DEVICE_CONTEXT_HEADER = SecurityPromptSectionCatalog.HEADER_DEVICE_CONTEXT;
    private static final String LOCATION_CONTEXT_HEADER = SecurityPromptSectionCatalog.HEADER_LOCATION_CONTEXT;
    private static final String INTENT_CONTEXT_HEADER = SecurityPromptSectionCatalog.HEADER_REQUEST_INTENT_SIGNAL_CONTEXT;
    private static final String RESOURCE_ACTION_HEADER = SecurityPromptSectionCatalog.HEADER_RESOURCE_AND_ACTION_CONTEXT;
    private static final String SESSION_NARRATIVE_HEADER = SecurityPromptSectionCatalog.HEADER_SESSION_NARRATIVE_CONTEXT;
    private static final String OBSERVED_WORK_PATTERN_HEADER = SecurityPromptSectionCatalog.HEADER_OBSERVED_WORK_PATTERN_CONTEXT;
    private static final String PERSONAL_WORK_PROFILE_HEADER = SecurityPromptSectionCatalog.HEADER_PERSONAL_WORK_PROFILE;
    private static final String SUPPORTING_LEARNING_CONTEXT_HEADER = SecurityPromptSectionCatalog.HEADER_SUPPORTING_LEARNING_CONTEXT;
    private static final String ROLE_SCOPE_HEADER = SecurityPromptSectionCatalog.HEADER_ROLE_AND_WORK_SCOPE_CONTEXT;
    private static final String EXPLICIT_MISSING_KNOWLEDGE_HEADER = SecurityPromptSectionCatalog.HEADER_EXPLICIT_MISSING_KNOWLEDGE;
    private static final String PEER_COHORT_HEADER = SecurityPromptSectionCatalog.HEADER_PEER_COHORT_DELTA;
    private static final String FRICTION_HEADER = SecurityPromptSectionCatalog.HEADER_FRICTION_AND_APPROVAL_HISTORY;
    private static final String DELEGATION_HEADER = SecurityPromptSectionCatalog.HEADER_DELEGATED_OBJECTIVE_CONTEXT;
    private static final String REASONING_MEMORY_HEADER = SecurityPromptSectionCatalog.HEADER_OUTCOME_AND_REASONING_MEMORY;
    private static final String THREAT_KNOWLEDGE_HEADER = "=== THREAT KNOWLEDGE PACK ===";
    private static final String THREAT_CAMPAIGN_HEADER = "=== ACTIVE THREAT CAMPAIGN MATCHES ===";
    private static final String OUTPUT_FORMAT_OPEN = "<output_format>";
    private static final String OUTPUT_FORMAT_CLOSE = "</output_format>";
    private static final String CONTEXT_OPEN = "<context>";
    private static final String CONTEXT_CLOSE = "</context>";
    private static final int COMPACT_SYSTEM_LINE_MAX_LENGTH = 320;

    private static final int CURRENT_REQUEST_SECTION_MAX_LINES = 14;
    private static final int BRIDGE_SECTION_MAX_LINES = 7;
    private static final int IDENTITY_SECTION_MAX_LINES = 6;
    private static final int AUTH_SECTION_MAX_LINES = 8;
    private static final int DEVICE_SECTION_MAX_LINES = 7;
    private static final int LOCATION_SECTION_MAX_LINES = 6;
    private static final int INTENT_SECTION_MAX_LINES = 6;
    private static final int RESOURCE_SECTION_MAX_LINES = 10;
    private static final int COVERAGE_MAX_MISSING_FACT_LINES = 2;
    private static final int COVERAGE_MAX_WARNING_LINES = 3;
    private static final int SESSION_SECTION_MAX_LINES = 16;
    private static final int WORK_PROFILE_SECTION_MAX_LINES = 16;
    private static final int SUPPORTING_LEARNING_SECTION_MAX_LINES = 8;
    private static final int ROLE_SCOPE_SECTION_MAX_LINES = 14;
    private static final int FRICTION_SECTION_MAX_LINES = 10;
    private static final int THREAT_SECTION_MAX_LINES = 10;
    private static final int DELEGATION_SECTION_MAX_LINES = 9;
    private static final int PEER_COHORT_SECTION_MAX_LINES = 7;
    private static final int MISSING_KNOWLEDGE_SECTION_MAX_LINES = 18;
    private static final int COMPACT_CURRENT_REQUEST_SECTION_MAX_LINES = 14;
    private static final int COMPACT_BRIDGE_SECTION_MAX_LINES = 7;
    private static final int COMPACT_IDENTITY_SECTION_MAX_LINES = 5;
    private static final int COMPACT_AUTH_SECTION_MAX_LINES = 8;
    private static final int COMPACT_DEVICE_SECTION_MAX_LINES = 6;
    private static final int COMPACT_LOCATION_SECTION_MAX_LINES = 5;
    private static final int COMPACT_INTENT_SECTION_MAX_LINES = 5;
    private static final int COMPACT_RESOURCE_SECTION_MAX_LINES = 10;
    private static final int COMPACT_COVERAGE_MAX_MISSING_FACT_LINES = 1;
    private static final int COMPACT_COVERAGE_MAX_WARNING_LINES = 2;
    private static final int COMPACT_SESSION_MAX_LINES = 16;
    private static final int COMPACT_WORK_PROFILE_SECTION_MAX_LINES = 16;
    private static final int COMPACT_SUPPORTING_LEARNING_SECTION_MAX_LINES = 9;
    private static final int COMPACT_ROLE_SCOPE_SECTION_MAX_LINES = 14;
    private static final int COMPACT_FRICTION_SECTION_MAX_LINES = 8;
    private static final int COMPACT_THREAT_SECTION_MAX_LINES = 7;
    private static final int COMPACT_MISSING_KNOWLEDGE_SECTION_MAX_LINES = 18;

    private static final Pattern DOC_META_PATTERN = Pattern.compile("\\|(?<key>[a-zA-Z0-9]+)=([^|\\]]+)");
    private static final Pattern BROWSER_PATTERN = Pattern.compile("using\\s+([^\\s]+)\\s+on\\s+");
    private static final Pattern OS_PATTERN = Pattern.compile("on\\s+(.+?)\\s+at\\s+");
    private static final Pattern ACTION_PATTERN = Pattern.compile("(?:autonomousAction|proposedAction)=([A-Z_]+)");

    private static final List<String> SESSION_PRIORITY_PREFIXES = List.of(
            "Requests in this session:",
            "HistoricalComparableScope:",
            "HistoricalComparableCount:",
            "HistoricalComparableSummary:",
            "ComparableExample1:",
            "PreviousPath:",
            "LastRequestIntervalMs:",
            "SessionActionSequence:",
            "SessionProtectableSequence:",
            "SessionTimelineSupport:",
            "PreviousActionFamily:",
            "BurstPattern:");

    private static final List<String> SESSION_REQUIRED_PREFIXES = List.of(
            "SessionNarrativeSummary:",
            "HistoricalComparableScope:",
            "HistoricalComparableCount:",
            "HistoricalComparableSummary:",
            "ComparableExample1:");

    private static final List<String> WORK_PROFILE_PRIORITY_PREFIXES = List.of(
            "BaselineProfileStatus:",
            "PersonalBaselineStatus:",
            "ObservedPatternEvidenceScope:",
            "BaselineObservations:",
            "ObservedHours:",
            "ObservedDays:",
            "CurrentVsObservedDeltaCount:",
            "StrongestCurrentVsObservedDelta:",
            "CurrentVsObservedDeltaSummary:",
            "CurrentRequestCombinationEvidenceScope:",
            "CurrentRequestCombinationSeenCount:",
            "CurrentRequestCombinationComparedDimensions:",
            "CurrentRequestClosestObservedOverlap:",
            "StrongestCurrentRequestCombinationDelta:",
            "CurrentRequestCombinationSummary:",
            "ObservedComparableCombination1:",
            "CurrentAccessHour:",
            "CurrentAccessHourPresentInObservedHours:",
            "CurrentPathFamily:",
            "CurrentPathPresentInObservedPaths:",
            "CurrentAuthenticationType:",
            "CurrentAuthenticationTypePresentInObservedAuthTypes:",
            "CurrentActionFamily:",
            "CurrentActionFamilyPresentInObservedActions:",
            "CurrentResourceFamily:",
            "CurrentResourceFamilyPresentInObservedResources:",
            "CurrentNetwork:",
            "CurrentNetworkPresentInObservedNetworks:",
            "CurrentBrowser:",
            "CurrentBrowserPresentInObservedBrowsers:",
            "CurrentOperatingSystem:",
            "CurrentOperatingSystemPresentInObservedOperatingSystems:",
            "CurrentDayOfWeek:",
            "CurrentDayPresentInObservedDays:",
            "WorkProfileEvidenceState:",
            "WorkProfileSummary:",
            "CurrentResourcePresentInObservedHistory:",
            "CurrentActionFamilyPresentInObservedHistory:",
            "ObservedAuthenticationTypes:",
            "ObservedActionFamilies:",
            "ObservedResourceFamilies:",
            "FrequentProtectableResources:",
            "FrequentActionFamilies:",
            "ProtectableInvocationDensity:",
            "NormalReadWriteExportRatio:",
            "ContextTrustWarning:",
            "ContextEvidenceLimitation:",
            "ContextTrustLimitation:",
            "NormalAccessHours:",
            "NormalAccessDays:",
            "TopPaths:",
            "TopHours:",
            "TopDays:",
            "TopBrowsers:",
            "TopOperatingSystems:");

    private static final List<String> WORK_PROFILE_REQUIRED_PREFIXES = List.of(
            "BaselineProfileStatus:",
            "PersonalBaselineStatus:",
            "WorkProfileEvidenceState:",
            "ObservedPatternEvidenceScope:",
            "BaselineObservations:",
            "ObservedHours:",
            "ObservedDays:",
            "CurrentVsObservedDeltaCount:",
            "StrongestCurrentVsObservedDelta:",
            "CurrentVsObservedDeltaSummary:",
            "CurrentRequestCombinationEvidenceScope:",
            "CurrentRequestCombinationSeenCount:",
            "CurrentRequestCombinationComparedDimensions:",
            "CurrentRequestClosestObservedOverlap:",
            "StrongestCurrentRequestCombinationDelta:",
            "CurrentRequestCombinationSummary:",
            "ObservedComparableCombination1:",
            "WorkProfileEvidenceState:",
            "CurrentAccessHour:",
            "CurrentAccessHourPresentInObservedHours:",
            "CurrentDayOfWeek:",
            "CurrentDayPresentInObservedDays:",
            "CurrentNetwork:",
            "CurrentNetworkPresentInObservedNetworks:",
            "CurrentBrowser:",
            "CurrentBrowserPresentInObservedBrowsers:",
            "CurrentOperatingSystem:",
            "CurrentOperatingSystemPresentInObservedOperatingSystems:",
            "CurrentPathFamily:",
            "CurrentPathPresentInObservedPaths:",
            "CurrentAuthenticationType:",
            "CurrentAuthenticationTypePresentInObservedAuthTypes:",
            "CurrentActionFamily:",
            "CurrentActionFamilyPresentInObservedActions:",
            "CurrentResourceFamily:",
            "CurrentResourceFamilyPresentInObservedResources:");

    private static final List<String> CURRENT_REQUEST_REQUIRED_PREFIXES = List.of(
            "AuthorizationEffectProvenance:",
            "AuthorizationEffectStageNote:",
            "User is requesting ",
            "MfaVerified:",
            "FailedLoginAttempts:");

    private static final List<String> ROLE_SCOPE_PRIORITY_PREFIXES = List.of(
            "RoleScopeEvidenceState:",
            "RoleScopeSummary:",
            "RoleScopeDeltaCount:",
            "StrongestRoleScopeDelta:",
            "RoleScopeDeltaSummary:",
            "CurrentResourceFamily:",
            "CurrentActionFamily:",
            "ExpectedResourceFamilies:",
            "ExpectedActionFamilies:",
            "ForbiddenResourceFamilies:",
            "ForbiddenActionFamilies:",
            "CurrentActionFamilyPresentInExpectedRoleScope:",
            "CurrentResourceFamilyPresentInExpectedRoleScope:",
            "RecentPermissionChanges:",
            "TemporaryElevation:",
            "ElevatedPrivilegeWindowActive:",
            "ElevationWindowSummary:");

    private static final List<String> ROLE_SCOPE_REQUIRED_PREFIXES = List.of(
            "RoleScopeEvidenceState:",
            "RoleScopeDeltaCount:",
            "StrongestRoleScopeDelta:",
            "RoleScopeDeltaSummary:",
            "CurrentActionFamilyPresentInExpectedRoleScope:",
            "CurrentResourceFamilyPresentInExpectedRoleScope:",
            "RecentPermissionChanges:");

    private static final List<String> SUPPORTING_LEARNING_PRIORITY_PREFIXES = List.of(
            "SupportingEvidenceMode:",
            "SupportingEvidenceNeverReplacesPersonalBaseline:",
            "SupportingBaselineStatus:",
            "SupportingBaselineSummary:",
            "SupportingComparableCount:",
            "SupportingComparableSummary:",
            "SupportingComparableExample1:",
            "SupportingEvidenceConstraint:");

    private static final List<String> SUPPORTING_LEARNING_REQUIRED_PREFIXES = List.of(
            "SupportingEvidenceMode:",
            "SupportingEvidenceNeverReplacesPersonalBaseline:",
            "SupportingBaselineStatus:",
            "SupportingComparableCount:",
            "SupportingComparableSummary:",
            "SupportingComparableExample1:",
            "SupportingEvidenceConstraint:");

    private static final List<String> FRICTION_PRIORITY_PREFIXES = List.of(
            "FrictionSummary:",
            "RecentChallengeCount:",
            "RecentBlockCount:",
            "RecentEscalationCount:",
            "ApprovalRequired:",
            "ApprovalGranted:",
            "ApprovalMissing:",
            "ApprovalStatus:",
            "ApprovalLineage:",
            "PendingApproverRoles:",
            "ApprovalTicketId:",
            "ApprovalDecisionAgeMinutes:",
            "BreakGlass:",
            "RecentDeniedAccessCount:",
            "BlockedUser:");

    private static final List<String> FRICTION_REQUIRED_PREFIXES = List.of(
            "ApprovalRequired:",
            "ApprovalGranted:",
            "ApprovalMissing:",
            "ApprovalStatus:");

    private static final List<String> THREAT_PRIORITY_PREFIXES = List.of(
            "ReasoningMemorySummary:",
            "ReinforcedCaseCount:",
            "HardNegativeCaseCount:",
            "FalseNegativeCaseCount:",
            "KnowledgeAssistedCaseCount:",
            "FreshnessState:",
            "ReasoningState:",
            "MemoryRiskProfile:",
            "MatchedSignalKeys:",
            "MemoryGuardrails:",
            "XaiLinkedFacts:",
            "1. ThreatClass:",
            "2. ThreatClass:",
            "3. ThreatClass:",
            "   Why this case is comparable:",
            "   Campaign summary:",
            "   Observed effect status:",
            "   XAI summary:");

    private static final List<String> DELEGATION_PRIORITY_PREFIXES = List.of(
            "Delegated:",
            "ObjectiveFamily:",
            "ObjectiveSummary:",
            "AllowedOperations:",
            "AllowedResources:",
            "ApprovalRequired:",
            "PrivilegedExportAllowed:",
            "ContainmentOnly:",
            "ObjectiveAlignmentEvidence:");

    private static final List<String> DELEGATION_REQUIRED_PREFIXES = List.of(
            "Delegated:",
            "ObjectiveFamily:",
            "ObjectiveSummary:",
            "ObjectiveAlignmentEvidence:");

    private static final List<String> PEER_COHORT_PRIORITY_PREFIXES = List.of(
            "PeerCohortId:",
            "PeerCohortSummary:",
            "CohortPreferredResources:",
            "CohortPreferredActionFamilies:",
            "CohortNormalProtectableFrequencyBand:",
            "CohortNormalSensitivityBand:",
            "CurrentResourcePresentInPeerPreferredResources:",
            "CurrentActionFamilyPresentInPeerPreferredActions:");

    private static final List<String> MISSING_KNOWLEDGE_PRIORITY_PREFIXES = List.of(
            "BaselineGapSupport:",
            "  STATUS:",
            "  IMPACT:",
            "  BASELINE EVIDENCE CONSTRAINTS:",
            "- Remediation:",
            "- ConfidenceWarning:",
            "- ContextEvidenceLimitation:",
            "- ContextTrustLimitation:",
            "- ContextTrustWarning:",
            "- ContextFieldLimitation:");

    private static final List<String> MISSING_KNOWLEDGE_REQUIRED_PREFIXES = List.of(
            "BaselineGapSupport:",
            "  STATUS:",
            "  IMPACT:",
            "  BASELINE EVIDENCE CONSTRAINTS:",
            "- ConfidenceWarning:",
            "- ContextEvidenceLimitation:",
            "- ContextTrustLimitation:",
            "- ContextTrustWarning:");

    private static final List<String> CURRENT_REQUEST_PRIORITY_PREFIXES = List.of(
            "AuthorizationContext:",
            "AuthorizationEffectProvenance:",
            "AuthorizationEffectStageNote:",
            "User:",
            "User is requesting ",
            "HttpMethod:",
            "NewDevice:",
            "NewSession:",
            "NewUser:",
            "MfaVerified:",
            "FailedLoginAttempts:");

    private static final List<String> DEVICE_PRIORITY_PREFIXES = List.of(
            "DeviceOs:",
            "DeviceBrowser:",
            "DeviceBrowserVersion:",
            "DeviceOsVersion:",
            "DeviceLanguage:",
            "DeviceScreenResolution:",
            "DeviceFingerprintMatch:");

    private static final List<String> LOCATION_PRIORITY_PREFIXES = List.of(
            "Country:",
            "City:",
            "IpBand:",
            "Asn:");

    private static final List<String> INTENT_PRIORITY_PREFIXES = List.of(
            "ImpossibleTravel:",
            "BotUserAgent:",
            "MissingReferer:",
            "LanguageMismatch:",
            "TlsFingerprintAltered:",
            "AbnormalHeaderOrder:");

    private static final List<String> BRIDGE_PRIORITY_PREFIXES = List.of(
            "BridgeCompletenessLevel:",
            "BridgeCompletenessSummary:",
            "BridgeMissingContexts:",
            "BridgeAuthenticationSource:",
            "BridgeAuthorizationSource:",
            "AuthorizationEffectProvenance:",
            "AuthorizationEffectStageNote:");

    private static final List<String> IDENTITY_PRIORITY_PREFIXES = List.of(
            "AuthorizationEffect:",
            "EffectiveRoles:",
            "EffectivePermissions:",
            "UserId:",
            "PrincipalType:",
            "RoleSet:");

    private static final List<String> AUTH_PRIORITY_PREFIXES = List.of(
            "SessionId:",
            "AuthenticationType:",
            "CurrentAccessHour:",
            "MfaVerified:",
            "NewDevice:",
            "RecentRequestCount:",
            "FailedLoginAttempts:",
            "NewSession:",
            "NewUser:");

    private static final List<String> RESOURCE_PRIORITY_PREFIXES = List.of(
            "RequestPath:",
            "ResourceId:",
            "HttpMethod:",
            "ResourceType:",
            "BusinessLabel:",
            "Sensitivity:",
            "ActionFamily:",
            "SensitiveResource:");

    private static final List<String> RESOURCE_REQUIRED_PREFIXES = List.of(
            "RequestPath:",
            "ResourceId:",
            "HttpMethod:",
            "ActionFamily:",
            "ResourceType:",
            "BusinessLabel:",
            "Sensitivity:");

    private final boolean compressionEnabled;

    public SafePromptNormalizationLLMViewComposer() {
        this(true);
    }

    public SafePromptNormalizationLLMViewComposer(boolean compressionEnabled) {
        this.compressionEnabled = compressionEnabled;
    }

    @Override
    public PromptViewComposition compose(String rawSystemPrompt, String rawUserPrompt, PromptBudgetProfile budgetProfile) {
        return compose(rawSystemPrompt, rawUserPrompt, budgetProfile, null);
    }

    @Override
    public PromptViewComposition compose(
            String rawSystemPrompt,
            String rawUserPrompt,
            PromptBudgetProfile budgetProfile,
            String modelHint) {
        String previousModelHint = ESTIMATION_MODEL_HINT.get();
        if (modelHint == null || modelHint.isBlank()) {
            ESTIMATION_MODEL_HINT.remove();
        } else {
            ESTIMATION_MODEL_HINT.set(modelHint);
        }
        try {
            return composeInternal(rawSystemPrompt, rawUserPrompt, budgetProfile);
        } finally {
            if (previousModelHint == null || previousModelHint.isBlank()) {
                ESTIMATION_MODEL_HINT.remove();
            } else {
                ESTIMATION_MODEL_HINT.set(previousModelHint);
            }
        }
    }

    private PromptViewComposition composeInternal(
            String rawSystemPrompt,
            String rawUserPrompt,
            PromptBudgetProfile budgetProfile) {
        PromptBudgetProfile effectiveProfile = budgetProfile != null
                ? budgetProfile
                : PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT;
        if (effectiveProfile.viewProfile() == PromptViewProfile.IDENTITY) {
            String rawSystem = rawSystemPrompt != null ? rawSystemPrompt : "";
            String rawUser = rawUserPrompt != null ? rawUserPrompt : "";
            return new PromptViewComposition(
                    rawSystem,
                    rawUser,
                    rawSystem,
                    rawUser,
                    buildLedger(rawSystem, rawUser, rawSystem, rawUser, List.of()));
        }

        String normalizedRawSystemPrompt = normalizeLineEndings(rawSystemPrompt);
        String normalizedRawUserPrompt = normalizeLineEndings(rawUserPrompt);
        String normalizedSystemPrompt = compactWhitespace(normalizedRawSystemPrompt);
        String normalizedUserPrompt = compactWhitespace(normalizedRawUserPrompt);

        List<PromptCompressionRecord> records = new ArrayList<>();
        if (!rawEquals(normalizedRawSystemPrompt, normalizedSystemPrompt)) {
            records.add(layoutRecord("SYSTEM_PROMPT_LAYOUT", normalizedRawSystemPrompt, normalizedSystemPrompt));
        }
        if (!rawEquals(normalizedRawUserPrompt, normalizedUserPrompt)) {
            records.add(layoutRecord("USER_PROMPT_LAYOUT", normalizedRawUserPrompt, normalizedUserPrompt));
        }

        if (preserveFullFinalUserPrompt(effectiveProfile)) {
            PromptTransformResult authorizationMissingContextFilter =
                    removeResolvedAuthorizationEffectMissingContext(normalizedUserPrompt);
            records.addAll(authorizationMissingContextFilter.records());
            return new PromptViewComposition(
                    normalizedRawSystemPrompt,
                    normalizedRawUserPrompt,
                    normalizedSystemPrompt,
                    authorizationMissingContextFilter.text(),
                    buildLedger(
                            normalizedRawSystemPrompt,
                            normalizedRawUserPrompt,
                            normalizedSystemPrompt,
                            authorizationMissingContextFilter.text(),
                            records));
        }

        if (!compressionEnabled) {
            PromptTransformResult authorizationMissingContextFilter = removeResolvedAuthorizationEffectMissingContext(normalizedUserPrompt);
            records.addAll(authorizationMissingContextFilter.records());
            return new PromptViewComposition(
                    normalizedRawSystemPrompt,
                    normalizedRawUserPrompt,
                    normalizedSystemPrompt,
                    authorizationMissingContextFilter.text(),
                    buildLedger(normalizedRawSystemPrompt, normalizedRawUserPrompt, normalizedSystemPrompt, authorizationMissingContextFilter.text(), records));
        }

        boolean forceSystemPromptCompaction = shouldForceSystemPromptCompaction(normalizedSystemPrompt, normalizedUserPrompt, effectiveProfile);
        PromptTransformResult systemPromptTransform = compactSystemPrompt(normalizedSystemPrompt, effectiveProfile, forceSystemPromptCompaction);
        records.addAll(systemPromptTransform.records());

        PromptTransformResult authorizationMissingContextFilter = removeResolvedAuthorizationEffectMissingContext(normalizedUserPrompt);
        records.addAll(authorizationMissingContextFilter.records());

        PromptTransformResult similarPastEvents = compactSimilarPastEventsSection(authorizationMissingContextFilter.text());
        records.addAll(similarPastEvents.records());

        PromptTransformResult currentRequest = compactSectionByPriority(
                similarPastEvents.text(),
                CURRENT_REQUEST_HEADER,
                CURRENT_REQUEST_REQUIRED_PREFIXES,
                CURRENT_REQUEST_PRIORITY_PREFIXES,
                CURRENT_REQUEST_SECTION_MAX_LINES,
                "CURRENT_REQUEST_AND_EVENT",
                "Current request retained the decisive request, provenance, and network anchors while compacting repeated detail lines.");
        records.addAll(currentRequest.records());

        PromptTransformResult bridgeResolution = compactBridgeSection(
                currentRequest.text(),
                "BRIDGE_RESOLUTION",
                "Bridge resolution retained completeness and missing-context anchors while compacting duplicated remediation detail.");
        records.addAll(bridgeResolution.records());

        PromptTransformResult coverage = compactCoverageSection(
                bridgeResolution.text(),
                COVERAGE_MAX_MISSING_FACT_LINES,
                COVERAGE_MAX_WARNING_LINES,
                "CONTEXT_COVERAGE",
                "Context coverage retained level, summary, critical gaps, and highest-value uncertainty warnings while compacting audit-heavy lists.");
        records.addAll(coverage.records());

        PromptTransformResult identity = compactSectionByPriority(
                coverage.text(),
                IDENTITY_ROLE_HEADER,
                IDENTITY_PRIORITY_PREFIXES,
                IDENTITY_SECTION_MAX_LINES,
                "IDENTITY_AND_ROLE",
                "Identity and role context retained subject, effective role, and authorization anchors while compacting secondary identity detail.");
        records.addAll(identity.records());

        PromptTransformResult authentication = compactSectionByPriority(
                identity.text(),
                AUTH_ASSURANCE_HEADER,
                AUTH_PRIORITY_PREFIXES,
                AUTH_SECTION_MAX_LINES,
                "AUTHENTICATION_AND_ASSURANCE",
                "Authentication context retained assurance and session-state anchors while compacting duplicate request detail.");
        records.addAll(authentication.records());

        PromptTransformResult deviceContext = compactSectionByPriority(
                authentication.text(),
                DEVICE_CONTEXT_HEADER,
                DEVICE_PRIORITY_PREFIXES,
                DEVICE_SECTION_MAX_LINES,
                "DEVICE_CONTEXT",
                "Device context retained operating-system, browser, and fingerprint anchors while compacting lower-value device detail.");
        records.addAll(deviceContext.records());

        PromptTransformResult locationContext = compactSectionByPriority(
                deviceContext.text(),
                LOCATION_CONTEXT_HEADER,
                LOCATION_PRIORITY_PREFIXES,
                LOCATION_SECTION_MAX_LINES,
                "LOCATION_CONTEXT",
                "Location context retained country, city, IP band, and ASN anchors while compacting redundant geography detail.");
        records.addAll(locationContext.records());

        PromptTransformResult intentContext = compactSectionByPriority(
                locationContext.text(),
                INTENT_CONTEXT_HEADER,
                INTENT_PRIORITY_PREFIXES,
                INTENT_SECTION_MAX_LINES,
                "INTENT_SIGNAL_CONTEXT",
                "Intent context retained explicit request-intent signals while compacting lower-value signal detail.");
        records.addAll(intentContext.records());

        PromptTransformResult resource = compactSectionByPriority(
                intentContext.text(),
                RESOURCE_ACTION_HEADER,
                RESOURCE_REQUIRED_PREFIXES,
                RESOURCE_PRIORITY_PREFIXES,
                RESOURCE_SECTION_MAX_LINES,
                "RESOURCE_AND_ACTION",
                "Resource context retained request path, action family, and sensitivity anchors while compacting duplicate resource detail.");
        records.addAll(resource.records());

        PromptTransformResult sessionNarrative = compactSectionByPriority(
                resource.text(),
                SESSION_NARRATIVE_HEADER,
                SESSION_REQUIRED_PREFIXES,
                SESSION_PRIORITY_PREFIXES,
                SESSION_SECTION_MAX_LINES,
                "SESSION_NARRATIVE",
                "Session narrative retained primary anchors and compacted verbose support lines.");
        records.addAll(sessionNarrative.records());

        PromptTransformResult observedWorkPattern = compactSectionByPriority(
                sessionNarrative.text(),
                OBSERVED_WORK_PATTERN_HEADER,
                WORK_PROFILE_REQUIRED_PREFIXES,
                WORK_PROFILE_PRIORITY_PREFIXES,
                WORK_PROFILE_SECTION_MAX_LINES,
                "OBSERVED_WORK_PATTERN",
                "Observed work pattern retained summary anchors and compacted lower-value support lines.");
        records.addAll(observedWorkPattern.records());

        PromptTransformResult personalWorkProfile = compactSectionByPriority(
                observedWorkPattern.text(),
                PERSONAL_WORK_PROFILE_HEADER,
                WORK_PROFILE_REQUIRED_PREFIXES,
                WORK_PROFILE_PRIORITY_PREFIXES,
                WORK_PROFILE_SECTION_MAX_LINES,
                "PERSONAL_WORK_PROFILE",
                "Personal work profile retained high-value baseline anchors and compacted supporting detail lines.");
        records.addAll(personalWorkProfile.records());

        PromptTransformResult supportingLearning = compactSectionByPriority(
                personalWorkProfile.text(),
                SUPPORTING_LEARNING_CONTEXT_HEADER,
                SUPPORTING_LEARNING_REQUIRED_PREFIXES,
                SUPPORTING_LEARNING_PRIORITY_PREFIXES,
                SUPPORTING_LEARNING_SECTION_MAX_LINES,
                "SUPPORTING_LEARNING_CONTEXT",
                "Supporting learning context retained reference-only anchors and compacted lower-value supporting detail.");
        records.addAll(supportingLearning.records());

        PromptTransformResult roleScope = compactSectionByPriority(
                supportingLearning.text(),
                ROLE_SCOPE_HEADER,
                ROLE_SCOPE_REQUIRED_PREFIXES,
                ROLE_SCOPE_PRIORITY_PREFIXES,
                ROLE_SCOPE_SECTION_MAX_LINES,
                "ROLE_SCOPE",
                "Role scope retained effective scope anchors and compacted supporting comparison lines.");
        records.addAll(roleScope.records());

        PromptTransformResult missingKnowledge = compactSectionByPriority(
                roleScope.text(),
                EXPLICIT_MISSING_KNOWLEDGE_HEADER,
                MISSING_KNOWLEDGE_REQUIRED_PREFIXES,
                MISSING_KNOWLEDGE_PRIORITY_PREFIXES,
                MISSING_KNOWLEDGE_SECTION_MAX_LINES,
                "EXPLICIT_MISSING_KNOWLEDGE",
                "Missing-knowledge context retained highest-value uncertainty anchors and compacted repeated warning lines.");
        records.addAll(missingKnowledge.records());

        PromptTransformResult friction = compactSectionByPriority(
                missingKnowledge.text(),
                FRICTION_HEADER,
                FRICTION_REQUIRED_PREFIXES,
                FRICTION_PRIORITY_PREFIXES,
                FRICTION_SECTION_MAX_LINES,
                "FRICTION_AND_APPROVAL",
                "Friction history retained latest challenge and approval anchors and compacted supporting history.");
        records.addAll(friction.records());

        PromptTransformResult delegation = compactSectionByPriority(
                friction.text(),
                DELEGATION_HEADER,
                DELEGATION_REQUIRED_PREFIXES,
                DELEGATION_PRIORITY_PREFIXES,
                DELEGATION_SECTION_MAX_LINES,
                "DELEGATED_OBJECTIVE",
                "Delegation context retained objective anchors and compacted secondary support lines.");
        records.addAll(delegation.records());

        PromptTransformResult reasoningMemory = compactSectionByPriority(
                delegation.text(),
                REASONING_MEMORY_HEADER,
                THREAT_PRIORITY_PREFIXES,
                THREAT_SECTION_MAX_LINES,
                "OUTCOME_AND_REASONING_MEMORY",
                "Reasoning memory retained summary anchors and compacted supporting fact lists.");
        records.addAll(reasoningMemory.records());

        PromptTransformResult threatKnowledge = compactSectionByPriority(
                reasoningMemory.text(),
                THREAT_KNOWLEDGE_HEADER,
                THREAT_PRIORITY_PREFIXES,
                THREAT_SECTION_MAX_LINES,
                "THREAT_KNOWLEDGE_PACK",
                "Threat knowledge retained comparable-case anchors and compacted lower-value support lines.");
        records.addAll(threatKnowledge.records());

        PromptTransformResult threatCampaign = compactSectionByPriority(
                threatKnowledge.text(),
                THREAT_CAMPAIGN_HEADER,
                THREAT_PRIORITY_PREFIXES,
                THREAT_SECTION_MAX_LINES,
                "THREAT_CAMPAIGN_MATCHES",
                "Threat campaign intelligence retained matched-signal anchors and compacted supporting lines.");
        records.addAll(threatCampaign.records());

        PromptTransformResult peerCohort = compactSectionByPriority(
                threatCampaign.text(),
                PEER_COHORT_HEADER,
                PEER_COHORT_PRIORITY_PREFIXES,
                PEER_COHORT_SECTION_MAX_LINES,
                "PEER_COHORT_DELTA",
                "Peer cohort context retained cohort summary anchors and compacted secondary support lines.");
        records.addAll(peerCohort.records());

        PromptTransformResult budgetEnforced = enforceBudget(
                systemPromptTransform.text(),
                peerCohort.text(),
                budgetProfile);
        records.addAll(budgetEnforced.records());

        PromptTransformResult deduplicatedFacts = deduplicateRepeatedFactLines(budgetEnforced.text());
        records.addAll(deduplicatedFacts.records());

        String llmSystemPrompt = systemPromptTransform.text();
        String llmUserPrompt = deduplicatedFacts.text();
        PromptCompressionLedger ledger = buildLedger(
                normalizedRawSystemPrompt,
                normalizedRawUserPrompt,
                llmSystemPrompt,
                llmUserPrompt,
                records);

        return new PromptViewComposition(
                normalizedRawSystemPrompt,
                normalizedRawUserPrompt,
                llmSystemPrompt,
                llmUserPrompt,
                ledger);
    }

    private boolean preserveFullFinalUserPrompt(PromptBudgetProfile effectiveProfile) {
        return effectiveProfile == PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT;
    }

    private PromptCompressionLedger buildLedger(
            String rawSystemPrompt,
            String rawUserPrompt,
            String llmSystemPrompt,
            String llmUserPrompt,
            List<PromptCompressionRecord> records) {
        int rawTotal = rawSystemPrompt.length() + rawUserPrompt.length();
        int llmTotal = llmSystemPrompt.length() + llmUserPrompt.length();
        int savedChars = Math.max(0, rawTotal - llmTotal);
        int savedTokens = Math.max(
                0,
                estimateTokens(rawSystemPrompt + "\n---\n" + rawUserPrompt)
                        - estimateTokens(llmSystemPrompt + "\n---\n" + llmUserPrompt));
        boolean parity = records.isEmpty();
        return new PromptCompressionLedger(
                resolveTransformationMode(records),
                parity,
                rawSystemPrompt.length(),
                rawUserPrompt.length(),
                llmSystemPrompt.length(),
                llmUserPrompt.length(),
                savedChars,
                savedTokens,
                records);
    }

    private PromptTransformResult removeResolvedAuthorizationEffectMissingContext(String prompt) {
        if (prompt == null || prompt.isBlank()
                || !prompt.contains("Bridge missing context: AUTHORIZATION_EFFECT.")
                || !hasResolvedAuthorizationEffect(prompt)) {
            return new PromptTransformResult(prompt != null ? prompt : "", List.of());
        }

        List<String> lines = Arrays.asList(prompt.split("\\n", -1));
        List<String> output = new ArrayList<>(lines.size());
        for (String line : lines) {
            if ("- Bridge missing context: AUTHORIZATION_EFFECT.".equals(line.trim())) {
                continue;
            }
            output.add(line);
        }
        String filtered = String.join("\n", output);
        if (filtered.equals(prompt)) {
            return new PromptTransformResult(prompt, List.of());
        }
        return new PromptTransformResult(
                filtered,
                List.of(new PromptCompressionRecord(
                        "EXPLICIT_MISSING_KNOWLEDGE",
                        PromptCompressionAction.OMITTED,
                        prompt.length(),
                        filtered.length(),
                        estimateSavedTokens(prompt, filtered),
                        "Removed stale AUTHORIZATION_EFFECT missing-context bullet because the final authorization effect is present.")));
    }

    private boolean hasResolvedAuthorizationEffect(String prompt) {
        for (String line : prompt.split("\\n")) {
            String trimmed = line.trim();
            if (!trimmed.startsWith("AuthorizationEffect:")) {
                continue;
            }
            String value = trimmed.substring("AuthorizationEffect:".length()).trim();
            return !value.isBlank()
                    && !"UNKNOWN".equalsIgnoreCase(value)
                    && !"UNRESOLVED".equalsIgnoreCase(value)
                    && !"MISSING".equalsIgnoreCase(value);
        }
        return false;
    }

    private String resolveTransformationMode(List<PromptCompressionRecord> records) {
        if (records.isEmpty()) {
            return "IDENTITY";
        }
        for (PromptCompressionRecord record : records) {
            if (record.action() == PromptCompressionAction.FUSED) {
                return NORMALIZE_AND_FUSE_MODE;
            }
        }
        for (PromptCompressionRecord record : records) {
            if (record.action() == PromptCompressionAction.SUMMARIZED) {
                return NORMALIZE_AND_COMPACT_MODE;
            }
        }
        return NORMALIZE_ONLY_MODE;
    }

    private boolean shouldForceSystemPromptCompaction(
            String systemPrompt,
            String userPrompt,
            PromptBudgetProfile budgetProfile) {
        PromptBudgetProfile effectiveProfile = budgetProfile != null ? budgetProfile : PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT;
        if (effectiveProfile.viewProfile() == PromptViewProfile.IDENTITY) {
            return false;
        }
        if (effectiveProfile.viewProfile() == PromptViewProfile.COMPACT) {
            return false;
        }
        if (effectiveProfile.expansionAllowed()) {
            return false;
        }
        String safeSystemPrompt = systemPrompt != null ? systemPrompt : "";
        String safeUserPrompt = userPrompt != null ? userPrompt : "";
        int estimatedTotalTokens = estimateTokens(safeSystemPrompt + "\n---\n" + safeUserPrompt);
        return estimatedTotalTokens > effectiveProfile.maxInputTokens();
    }

    private PromptTransformResult compactSystemPrompt(
            String systemPrompt,
            PromptBudgetProfile budgetProfile,
            boolean forceCompaction) {
        if (systemPrompt == null || systemPrompt.isBlank()) {
            return new PromptTransformResult("", List.of());
        }

        PromptBudgetProfile effectiveProfile = budgetProfile != null ? budgetProfile : PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT;
        boolean compactProfile = effectiveProfile.viewProfile() == PromptViewProfile.COMPACT;
        if (!compactProfile && !forceCompaction) {
            return new PromptTransformResult(systemPrompt, List.of());
        }

        String outputFormatBlock = extractTaggedBlock(systemPrompt, OUTPUT_FORMAT_OPEN, OUTPUT_FORMAT_CLOSE);
        String contextBlock = extractTaggedBlock(systemPrompt, CONTEXT_OPEN, CONTEXT_CLOSE);
        String corePrompt = removeTaggedBlock(systemPrompt, OUTPUT_FORMAT_OPEN, OUTPUT_FORMAT_CLOSE);
        corePrompt = removeTaggedBlock(corePrompt, CONTEXT_OPEN, CONTEXT_CLOSE);
        String compactCore = compactSystemCore(corePrompt);

        StringBuilder compacted = new StringBuilder(compactCore);
        appendTaggedBlock(compacted, OUTPUT_FORMAT_OPEN, outputFormatBlock, OUTPUT_FORMAT_CLOSE);
        appendTaggedBlock(compacted, CONTEXT_OPEN, contextBlock, CONTEXT_CLOSE);
        String compactedSystemPrompt = compactWhitespace(compacted.toString());
        if (compactedSystemPrompt.length() >= systemPrompt.length()) {
            return new PromptTransformResult(systemPrompt, List.of());
        }

        String reason = forceCompaction && !compactProfile
                ? "System prompt exceeded a non-expanding budget, so decisive zero-trust instructions and output contract were compacted before user-section budget enforcement."
                : "System prompt retained decisive zero-trust instructions, compact action semantics, and output contract while removing repetitive narrative guidance.";

        return new PromptTransformResult(
                compactedSystemPrompt,
                List.of(new PromptCompressionRecord(
                        "SYSTEM_PROMPT_DECISION_CONTRACT",
                        PromptCompressionAction.SUMMARIZED,
                        systemPrompt.length(),
                        compactedSystemPrompt.length(),
                        estimateSavedTokens(systemPrompt, compactedSystemPrompt),
                        reason)));
    }

    private String compactSystemCore(String systemPrompt) {
        if (systemPrompt == null || systemPrompt.isBlank()) {
            return "";
        }
        String[] rawLines = systemPrompt.split("\\R");
        List<String> compactedLines = new ArrayList<>();
        String previousLine = null;
        for (String rawLine : rawLines) {
            String normalizedLine = compactWhitespace(rawLine).trim();
            if (normalizedLine.isEmpty()) {
                continue;
            }
            if (normalizedLine.equals(previousLine)) {
                continue;
            }
            compactedLines.add(normalizedLine);
            previousLine = normalizedLine;
        }
        return String.join("\n", compactedLines);
    }

    private void appendTaggedBlock(StringBuilder builder, String openTag, String blockContent, String closeTag) {
        if (blockContent == null || blockContent.isBlank()) {
            return;
        }
        builder.append("\n\n")
                .append(openTag)
                .append("\n")
                .append(compactWhitespace(blockContent))
                .append("\n")
                .append(closeTag);
    }

    private String extractTaggedBlock(String text, String openTag, String closeTag) {
        if (text == null || text.isBlank()) {
            return null;
        }
        int openIndex = text.indexOf(openTag);
        if (openIndex < 0) {
            return null;
        }
        int contentStart = openIndex + openTag.length();
        int closeIndex = text.indexOf(closeTag, contentStart);
        if (closeIndex < 0) {
            return null;
        }
        return text.substring(contentStart, closeIndex).trim();
    }

    private String removeTaggedBlock(String text, String openTag, String closeTag) {
        if (text == null || text.isBlank()) {
            return text;
        }
        int openIndex = text.indexOf(openTag);
        if (openIndex < 0) {
            return text;
        }
        int closeIndex = text.indexOf(closeTag, openIndex + openTag.length());
        if (closeIndex < 0) {
            return text;
        }
        int blockEnd = closeIndex + closeTag.length();
        String prefix = text.substring(0, openIndex).trim();
        String suffix = text.substring(blockEnd).trim();
        if (prefix.isEmpty()) {
            return suffix;
        }
        if (suffix.isEmpty()) {
            return prefix;
        }
        return prefix + "\n" + suffix;
    }

    private PromptCompressionRecord layoutRecord(String scopeKey, String rawText, String compactText) {
        return new PromptCompressionRecord(
                scopeKey,
                PromptCompressionAction.TRIMMED,
                rawText.length(),
                compactText.length(),
                estimateSavedTokens(rawText, compactText),
                "Whitespace-only normalization removed trailing spaces, excess blank lines, or terminal blank lines.");
    }

    private PromptTransformResult compactSimilarPastEventsSection(String userPrompt) {
        return compactNamedSection(userPrompt, SIMILAR_PAST_EVENTS_HEADER, "SIMILAR_PAST_EVENTS", sectionLines -> {
            List<Integer> docIndexes = new ArrayList<>();
            for (int i = 0; i < sectionLines.size(); i++) {
                if (sectionLines.get(i).startsWith("[Doc")) {
                    docIndexes.add(i);
                }
            }
            if (docIndexes.size() <= 2) {
                return SectionTransform.identity(sectionLines);
            }

            int firstDocIndex = docIndexes.get(0);
            int lastDocIndex = docIndexes.get(docIndexes.size() - 1);
            List<String> docLines = new ArrayList<>(docIndexes.size());
            for (Integer docIndex : docIndexes) {
                docLines.add(sectionLines.get(docIndex));
            }

            List<String> compacted = new ArrayList<>(sectionLines.size());
            for (int i = 0; i < firstDocIndex; i++) {
                compacted.add(sectionLines.get(i));
            }
            compacted.add(buildFusedComparableSummary(docLines));
            compacted.add(docLines.get(0));
            compacted.add(docLines.get(1));
            compacted.add("+ " + (docLines.size() - 2) + " additional comparable records fused into summary.");
            for (int i = lastDocIndex + 1; i < sectionLines.size(); i++) {
                compacted.add(sectionLines.get(i));
            }

            return SectionTransform.changed(
                    compacted,
                    PromptCompressionAction.FUSED,
                    "Comparable historical records were summarized first and only representative records were retained in the LLM view.");
        });
    }

    private PromptTransformResult compactBridgeSection(
            String prompt,
            String scopeKey,
            String reason) {
        return compactNamedSection(prompt, BRIDGE_RESOLUTION_HEADER, scopeKey, sectionLines -> {
            if (sectionLines == null || sectionLines.isEmpty()) {
                return SectionTransform.identity(sectionLines);
            }

            List<String> compacted = new ArrayList<>();
            compacted.add(sectionLines.get(0));
            appendFirstMatchingLine(compacted, sectionLines, "BridgeCompletenessLevel:");
            appendFirstMatchingLine(compacted, sectionLines, "BridgeCompletenessSummary:");
            appendFirstMatchingLine(compacted, sectionLines, "BridgeMissingContexts:");
            appendFirstMatchingLine(compacted, sectionLines, "BridgeAuthenticationSource:");
            appendFirstMatchingLine(compacted, sectionLines, "BridgeAuthorizationSource:");

            int remediationHints = countMatchingLines(sectionLines, "BridgeRemediationHints:");
            if (remediationHints > 0) {
                compacted.add("BridgeRemediationHintsCompacted: " + remediationHints);
            }
            if (compacted.equals(sectionLines)) {
                return SectionTransform.identity(sectionLines);
            }
            return SectionTransform.changed(compacted, PromptCompressionAction.SUMMARIZED, reason);
        });
    }

    private PromptTransformResult compactCoverageSection(
            String prompt,
            int maxMissingFacts,
            int maxWarnings,
            String scopeKey,
            String reason) {
        return compactNamedSection(prompt, COVERAGE_HEADER, scopeKey, sectionLines -> {
            List<String> compacted = retainCoverageLines(sectionLines, maxMissingFacts, maxWarnings);
            if (compacted.equals(sectionLines)) {
                return SectionTransform.identity(sectionLines);
            }
            return SectionTransform.changed(compacted, PromptCompressionAction.SUMMARIZED, reason);
        });
    }

    private List<String> retainCoverageLines(List<String> sectionLines, int maxMissingFacts, int maxWarnings) {
        if (sectionLines == null || sectionLines.isEmpty()) {
            return List.of();
        }

        List<String> compacted = new ArrayList<>();
        compacted.add(sectionLines.get(0));
        appendFirstMatchingLine(compacted, sectionLines, "CoverageLevel:");
        appendFirstMatchingLine(compacted, sectionLines, "CoverageSummary:");

        int availableFacts = countBulletBlockItems(sectionLines, "AvailableFacts:");
        int missingFacts = appendBulletBlock(compacted, sectionLines, "MissingCriticalFacts:", maxMissingFacts);
        int remediationHints = countBulletBlockItems(sectionLines, "RemediationHints:");
        int confidenceWarnings = appendBulletBlock(compacted, sectionLines, "ConfidenceWarnings:", maxWarnings);

        if (availableFacts > 0) {
            compacted.add("AvailableFactsCompacted: " + availableFacts);
        }
        if (missingFacts > maxMissingFacts) {
            compacted.add("AdditionalMissingCriticalFactsCompacted: " + (missingFacts - maxMissingFacts));
        }
        if (remediationHints > 0) {
            compacted.add("RemediationHintsCompacted: " + remediationHints);
        }
        if (confidenceWarnings > maxWarnings) {
            compacted.add("AdditionalConfidenceWarningsCompacted: " + (confidenceWarnings - maxWarnings));
        }
        return compacted;
    }

    private void appendFirstMatchingLine(List<String> target, List<String> lines, String prefix) {
        int index = findLineIndex(lines, prefix);
        if (index >= 0) {
            target.add(lines.get(index));
        }
    }

    private int appendBulletBlock(List<String> target, List<String> sectionLines, String header, int maxItems) {
        int start = findLineIndex(sectionLines, header);
        if (start < 0) {
            return 0;
        }

        List<String> bullets = new ArrayList<>();
        for (int i = start + 1; i < sectionLines.size(); i++) {
            String line = sectionLines.get(i);
            String trimmed = line.trim();
            if (line.startsWith("=== ")) {
                break;
            }
            if (line.endsWith(":") && !trimmed.startsWith("- ")) {
                break;
            }
            if (!trimmed.startsWith("- ")) {
                continue;
            }
            bullets.add(trimmed);
        }
        if (bullets.isEmpty()) {
            return 0;
        }
        target.add(header);
        int limit = Math.max(0, maxItems);
        for (int i = 0; i < bullets.size() && i < limit; i++) {
            target.add(bullets.get(i));
        }
        return bullets.size();
    }

    private int countBulletBlockItems(List<String> sectionLines, String header) {
        return appendBulletBlock(new ArrayList<>(), sectionLines, header, 0);
    }

    private int countMatchingLines(List<String> lines, String prefix) {
        if (lines == null || prefix == null) {
            return 0;
        }
        int matches = 0;
        for (String line : lines) {
            if (lineStartsWithPrefix(line, prefix)) {
                matches++;
            }
        }
        return matches;
    }

    private int findLineIndex(List<String> lines, String prefix) {
        if (lines == null || prefix == null) {
            return -1;
        }
        for (int i = 0; i < lines.size(); i++) {
            if (lineStartsWithPrefix(lines.get(i), prefix)) {
                return i;
            }
        }
        return -1;
    }

    private PromptTransformResult compactSectionByPriority(
            String prompt,
            String header,
            List<String> priorityPrefixes,
            int maxLines,
            String scopeKey,
            String reason) {
        return compactSectionByPriority(
                prompt,
                header,
                List.of(),
                priorityPrefixes,
                maxLines,
                scopeKey,
                reason);
    }

    private PromptTransformResult compactSectionByPriority(
            String prompt,
            String header,
            List<String> requiredPrefixes,
            List<String> priorityPrefixes,
            int maxLines,
            String scopeKey,
            String reason) {
        return compactNamedSection(prompt, header, scopeKey, sectionLines -> {
            if (sectionLines.size() <= maxLines) {
                return SectionTransform.identity(sectionLines);
            }

            List<String> compacted = retainPriorityLines(sectionLines, requiredPrefixes, priorityPrefixes, maxLines);
            if (compacted.equals(sectionLines)) {
                return SectionTransform.identity(sectionLines);
            }

            int removedLines = sectionLines.size() - compacted.size();
            String compactedCategories = summarizeCompactedLineCategories(sectionLines, compacted);
            if (StringUtils.hasText(compactedCategories)) {
                compacted.add("CompactedLineCategories: " + compactedCategories);
            }
            compacted.add("+ " + removedLines + " additional lines compacted.");
            return SectionTransform.changed(compacted, PromptCompressionAction.SUMMARIZED, reason);
        });
    }

    private String summarizeCompactedLineCategories(List<String> originalLines, List<String> retainedLines) {
        if (originalLines == null || originalLines.isEmpty()) {
            return null;
        }
        Set<String> retained = new LinkedHashSet<>(retainedLines != null ? retainedLines : List.of());
        Set<String> categories = new LinkedHashSet<>();
        for (int i = 1; i < originalLines.size(); i++) {
            String line = originalLines.get(i);
            if (!StringUtils.hasText(line) || retained.contains(line)) {
                continue;
            }
            String category = compactedLineCategory(line);
            if (StringUtils.hasText(category)) {
                categories.add(category);
            }
            if (categories.size() >= 8) {
                break;
            }
        }
        return categories.isEmpty() ? null : String.join(", ", categories);
    }

    private String compactedLineCategory(String line) {
        if (!StringUtils.hasText(line)) {
            return null;
        }
        String trimmed = line.strip();
        if (trimmed.startsWith("- ")) {
            return "bullet:" + trimmed.substring(2).split("[:|.]", 2)[0].trim();
        }
        int colon = trimmed.indexOf(':');
        if (colon > 0) {
            return trimmed.substring(0, colon).trim();
        }
        return trimmed.length() <= 40 ? trimmed : "supporting-detail";
    }

    private PromptTransformResult compactNamedSection(
            String prompt,
            String header,
            String scopeKey,
            SectionCompactor compactor) {
        if (prompt == null || prompt.isBlank() || !prompt.contains(header)) {
            return new PromptTransformResult(prompt != null ? prompt : "", List.of());
        }

        List<String> lines = new ArrayList<>(Arrays.asList(prompt.split("\\n", -1)));
        List<String> output = new ArrayList<>(lines.size());
        List<PromptCompressionRecord> records = new ArrayList<>();

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (!header.equals(line)) {
                output.add(line);
                continue;
            }

            int end = i + 1;
            while (end < lines.size() && !lines.get(end).startsWith("=== ")) {
                end++;
            }

            List<String> sectionLines = new ArrayList<>(lines.subList(i, end));
            SectionTransform sectionTransform = compactor.compact(sectionLines);
            output.addAll(sectionTransform.lines());
            if (sectionTransform.changed()) {
                String rawSection = String.join("\n", sectionLines);
                String compactSection = String.join("\n", sectionTransform.lines());
                records.add(new PromptCompressionRecord(
                        scopeKey,
                        sectionTransform.action(),
                        rawSection.length(),
                        compactSection.length(),
                        estimateSavedTokens(rawSection, compactSection),
                        sectionTransform.reason()));
            }
            i = end - 1;
        }

        return new PromptTransformResult(String.join("\n", output), records);
    }

    private PromptTransformResult deduplicateRepeatedFactLines(String prompt) {
        if (prompt == null || prompt.isBlank()) {
            return new PromptTransformResult("", List.of());
        }

        List<String> lines = Arrays.asList(prompt.split("\\n", -1));
        List<String> output = new ArrayList<>(lines.size());
        Map<String, String> seenFacts = new LinkedHashMap<>();
        Map<String, Integer> seenFactIndexes = new LinkedHashMap<>();
        int removed = 0;
        for (String line : lines) {
            FactLine factLine = extractRepeatedFactLine(line);
            if (factLine == null) {
                output.add(line);
                continue;
            }
            String key = factLine.group() + "=" + factLine.value();
            if (seenFacts.containsKey(key)) {
                int existingIndex = seenFactIndexes.getOrDefault(key, -1);
                String existingLine = seenFacts.get(key);
                if (existingIndex >= 0 && canonicalFactLinePriority(line) > canonicalFactLinePriority(existingLine)) {
                    output.set(existingIndex, line);
                    seenFacts.put(key, line);
                    removed++;
                    continue;
                }
                removed++;
                continue;
            }
            seenFacts.put(key, line);
            seenFactIndexes.put(key, output.size());
            output.add(line);
        }

        if (removed == 0) {
            return new PromptTransformResult(prompt, List.of());
        }

        String compacted = String.join("\n", output);
        return new PromptTransformResult(
                compacted,
                List.of(new PromptCompressionRecord(
                        "GLOBAL_REQUEST_FACTS",
                        PromptCompressionAction.DEDUPLICATED,
                        prompt.length(),
                        compacted.length(),
                        estimateSavedTokens(prompt, compacted),
                        "Repeated high-signal request facts were retained once to avoid duplicate evidence across sections.")));
    }

    private FactLine extractRepeatedFactLine(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }
        String normalizedLine = line.trim();
        return extractFact(normalizedLine, "RequestPath:", "PATH")
                .or(() -> extractFact(normalizedLine, "CurrentRequestPath:", "PATH"))
                .or(() -> extractFact(normalizedLine, "Path:", "PATH"))
                .or(() -> extractFact(normalizedLine, "ClientIp:", "IP"))
                .or(() -> extractFact(normalizedLine, "SourceIp:", "IP"))
                .or(() -> extractFact(normalizedLine, "IP:", "IP"))
                .or(() -> extractFact(normalizedLine, "User:", "USER"))
                .or(() -> extractFact(normalizedLine, "UserId:", "USER"))
                .or(() -> extractFact(normalizedLine, "HttpMethod:", "HTTP_METHOD"))
                .or(() -> extractFact(normalizedLine, "MfaVerified:", "MFA"))
                .or(() -> extractFact(normalizedLine, "FailedLoginAttempts:", "FAILED_LOGIN_ATTEMPTS"))
                .or(() -> extractFact(normalizedLine, "NewSession:", "NEW_SESSION"))
                .or(() -> extractFact(normalizedLine, "NewUser:", "NEW_USER"))
                .or(() -> extractFact(normalizedLine, "NewDevice:", "NEW_DEVICE"))
                .or(() -> extractFact(normalizedLine, "RecentRequestCount:", "RECENT_REQUEST_COUNT"))
                .or(() -> extractFact(normalizedLine, "Sensitivity:", "SENSITIVITY"))
                .or(() -> extractFact(normalizedLine, "ResourceSensitivity:", "SENSITIVITY"))
                .or(() -> extractFact(normalizedLine, "AuthorizationEffect:", "AUTHORIZATION_EFFECT"))
                .or(() -> extractFact(normalizedLine, "AuthMethod:", "AUTH_METHOD"))
                .orElse(null);
    }

    private int canonicalFactLinePriority(String line) {
        if (line == null) {
            return 0;
        }
        String normalized = line.trim();
        if (normalized.startsWith("RequestPath:")) {
            return 30;
        }
        if (normalized.startsWith("CurrentRequestPath:")) {
            return 20;
        }
        if (normalized.startsWith("Path:")) {
            return 10;
        }
        if (normalized.startsWith("ResourceSensitivity:")) {
            return 20;
        }
        if (normalized.startsWith("Sensitivity:")) {
            return 10;
        }
        return 10;
    }

    private java.util.Optional<FactLine> extractFact(String line, String prefix, String group) {
        if (line == null || !line.startsWith(prefix)) {
            return java.util.Optional.empty();
        }
        String value = line.substring(prefix.length()).trim();
        if (value.isBlank()) {
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(new FactLine(group, value));
    }

    private PromptTransformResult enforceBudget(
            String systemPrompt,
            String userPrompt,
            PromptBudgetProfile budgetProfile) {
        PromptBudgetProfile effectiveProfile = budgetProfile != null ? budgetProfile : PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT;
        String current = userPrompt != null ? userPrompt : "";
        List<PromptCompressionRecord> records = new ArrayList<>();
        int totalTokens = estimateTokens(systemPrompt + "\n---\n" + current);
        boolean compactProfile = effectiveProfile.viewProfile() == PromptViewProfile.COMPACT;
        if (!compactProfile && totalTokens <= effectiveProfile.maxInputTokens()) {
            return new PromptTransformResult(current, List.of());
        }

        PromptTransformResult compactCurrentRequest = compactSectionByPriority(
                current,
                CURRENT_REQUEST_HEADER,
                CURRENT_REQUEST_REQUIRED_PREFIXES,
                CURRENT_REQUEST_PRIORITY_PREFIXES,
                COMPACT_CURRENT_REQUEST_SECTION_MAX_LINES,
                "CURRENT_REQUEST_AND_EVENT_BUDGET",
                "Budget enforcement retained only the decisive request and provenance anchors.");
        current = compactCurrentRequest.text();
        records.addAll(compactCurrentRequest.records());

        PromptTransformResult compactBridge = compactBridgeSection(
                current,
                "BRIDGE_RESOLUTION_BUDGET",
                "Budget enforcement retained only the bridge completeness and missing-context anchors.");
        current = compactBridge.text();
        records.addAll(compactBridge.records());

        PromptTransformResult compactCoverage = compactCoverageSection(
                current,
                COMPACT_COVERAGE_MAX_MISSING_FACT_LINES,
                COMPACT_COVERAGE_MAX_WARNING_LINES,
                "CONTEXT_COVERAGE_BUDGET",
                "Budget enforcement retained only the strongest coverage summary, critical gap, and uncertainty anchors.");
        current = compactCoverage.text();
        records.addAll(compactCoverage.records());

        PromptTransformResult compactIdentity = compactSectionByPriority(
                current,
                IDENTITY_ROLE_HEADER,
                IDENTITY_PRIORITY_PREFIXES,
                COMPACT_IDENTITY_SECTION_MAX_LINES,
                "IDENTITY_AND_ROLE_BUDGET",
                "Budget enforcement retained only subject, role, and authorization anchors.");
        current = compactIdentity.text();
        records.addAll(compactIdentity.records());

        PromptTransformResult compactAuthentication = compactSectionByPriority(
                current,
                AUTH_ASSURANCE_HEADER,
                AUTH_PRIORITY_PREFIXES,
                COMPACT_AUTH_SECTION_MAX_LINES,
                "AUTHENTICATION_AND_ASSURANCE_BUDGET",
                "Budget enforcement retained only assurance and session-state anchors.");
        current = compactAuthentication.text();
        records.addAll(compactAuthentication.records());

        PromptTransformResult compactDevice = compactSectionByPriority(
                current,
                DEVICE_CONTEXT_HEADER,
                DEVICE_PRIORITY_PREFIXES,
                COMPACT_DEVICE_SECTION_MAX_LINES,
                "DEVICE_CONTEXT_BUDGET",
                "Budget enforcement retained only the decisive device anchors.");
        current = compactDevice.text();
        records.addAll(compactDevice.records());

        PromptTransformResult compactLocation = compactSectionByPriority(
                current,
                LOCATION_CONTEXT_HEADER,
                LOCATION_PRIORITY_PREFIXES,
                COMPACT_LOCATION_SECTION_MAX_LINES,
                "LOCATION_CONTEXT_BUDGET",
                "Budget enforcement retained only the decisive location anchors.");
        current = compactLocation.text();
        records.addAll(compactLocation.records());

        PromptTransformResult compactIntent = compactSectionByPriority(
                current,
                INTENT_CONTEXT_HEADER,
                INTENT_PRIORITY_PREFIXES,
                COMPACT_INTENT_SECTION_MAX_LINES,
                "INTENT_SIGNAL_CONTEXT_BUDGET",
                "Budget enforcement retained only the decisive request-intent anchors.");
        current = compactIntent.text();
        records.addAll(compactIntent.records());

        PromptTransformResult compactResource = compactSectionByPriority(
                current,
                RESOURCE_ACTION_HEADER,
                RESOURCE_REQUIRED_PREFIXES,
                RESOURCE_PRIORITY_PREFIXES,
                COMPACT_RESOURCE_SECTION_MAX_LINES,
                "RESOURCE_AND_ACTION_BUDGET",
                "Budget enforcement retained only request path, action family, and sensitivity anchors.");
        current = compactResource.text();
        records.addAll(compactResource.records());

        PromptTransformResult compactSession = compactSectionByPriority(
                current,
                SESSION_NARRATIVE_HEADER,
                SESSION_REQUIRED_PREFIXES,
                SESSION_PRIORITY_PREFIXES,
                COMPACT_SESSION_MAX_LINES,
                "SESSION_NARRATIVE_BUDGET",
                "Budget enforcement retained only the highest-value session anchors.");
        current = compactSession.text();
        records.addAll(compactSession.records());

        PromptTransformResult compactWorkPattern = compactSectionByPriority(
                current,
                OBSERVED_WORK_PATTERN_HEADER,
                WORK_PROFILE_REQUIRED_PREFIXES,
                WORK_PROFILE_PRIORITY_PREFIXES,
                COMPACT_WORK_PROFILE_SECTION_MAX_LINES,
                "OBSERVED_WORK_PATTERN_BUDGET",
                "Budget enforcement retained only the highest-value work-pattern anchors.");
        current = compactWorkPattern.text();
        records.addAll(compactWorkPattern.records());

        PromptTransformResult compactPersonalProfile = compactSectionByPriority(
                current,
                PERSONAL_WORK_PROFILE_HEADER,
                WORK_PROFILE_REQUIRED_PREFIXES,
                WORK_PROFILE_PRIORITY_PREFIXES,
                COMPACT_WORK_PROFILE_SECTION_MAX_LINES,
                "PERSONAL_WORK_PROFILE_BUDGET",
                "Budget enforcement retained only the highest-value baseline anchors.");
        current = compactPersonalProfile.text();
        records.addAll(compactPersonalProfile.records());

        PromptTransformResult compactSupportingLearning = compactSectionByPriority(
                current,
                SUPPORTING_LEARNING_CONTEXT_HEADER,
                SUPPORTING_LEARNING_REQUIRED_PREFIXES,
                SUPPORTING_LEARNING_PRIORITY_PREFIXES,
                COMPACT_SUPPORTING_LEARNING_SECTION_MAX_LINES,
                "SUPPORTING_LEARNING_CONTEXT_BUDGET",
                "Budget enforcement retained only the strongest supporting-learning anchors.");
        current = compactSupportingLearning.text();
        records.addAll(compactSupportingLearning.records());

        PromptTransformResult compactRoleScope = compactSectionByPriority(
                current,
                ROLE_SCOPE_HEADER,
                ROLE_SCOPE_REQUIRED_PREFIXES,
                ROLE_SCOPE_PRIORITY_PREFIXES,
                COMPACT_ROLE_SCOPE_SECTION_MAX_LINES,
                "ROLE_SCOPE_BUDGET",
                "Budget enforcement retained only the current-vs-expected scope anchors.");
        current = compactRoleScope.text();
        records.addAll(compactRoleScope.records());

        PromptTransformResult compactMissingKnowledge = compactSectionByPriority(
                current,
                EXPLICIT_MISSING_KNOWLEDGE_HEADER,
                MISSING_KNOWLEDGE_REQUIRED_PREFIXES,
                MISSING_KNOWLEDGE_PRIORITY_PREFIXES,
                COMPACT_MISSING_KNOWLEDGE_SECTION_MAX_LINES,
                "EXPLICIT_MISSING_KNOWLEDGE_BUDGET",
                "Budget enforcement retained only the strongest uncertainty and remediation anchors.");
        current = compactMissingKnowledge.text();
        records.addAll(compactMissingKnowledge.records());

        PromptTransformResult compactFriction = compactSectionByPriority(
                current,
                FRICTION_HEADER,
                FRICTION_REQUIRED_PREFIXES,
                FRICTION_PRIORITY_PREFIXES,
                COMPACT_FRICTION_SECTION_MAX_LINES,
                "FRICTION_AND_APPROVAL_BUDGET",
                "Budget enforcement retained only the latest friction and approval anchors.");
        current = compactFriction.text();
        records.addAll(compactFriction.records());

        PromptTransformResult compactReasoningMemory = compactSectionByPriority(
                current,
                REASONING_MEMORY_HEADER,
                THREAT_PRIORITY_PREFIXES,
                COMPACT_THREAT_SECTION_MAX_LINES,
                "OUTCOME_AND_REASONING_MEMORY_BUDGET",
                "Budget enforcement retained only the highest-value memory anchors.");
        current = compactReasoningMemory.text();
        records.addAll(compactReasoningMemory.records());

        totalTokens = estimateTokens(systemPrompt + "\n---\n" + current);
        if (totalTokens > effectiveProfile.maxInputTokens() || effectiveProfile.supportingSectionOmissionAllowed()) {
            current = omitSupportingSectionsUntilBudget(
                    systemPrompt,
                    current,
                    effectiveProfile,
                    records);
        }

        return new PromptTransformResult(current, records);
    }

    private String omitSupportingSectionsUntilBudget(
            String systemPrompt,
            String currentPrompt,
            PromptBudgetProfile budgetProfile,
            List<PromptCompressionRecord> records) {
        String current = currentPrompt;
        List<SectionOmissionPlan> omissionPlans = List.of(
                new SectionOmissionPlan(PEER_COHORT_HEADER, "PEER_COHORT_DELTA_BUDGET"),
                new SectionOmissionPlan(REASONING_MEMORY_HEADER, "OUTCOME_AND_REASONING_MEMORY_BUDGET_OMISSION"),
                new SectionOmissionPlan(THREAT_KNOWLEDGE_HEADER, "THREAT_KNOWLEDGE_PACK_BUDGET_OMISSION"),
                new SectionOmissionPlan(THREAT_CAMPAIGN_HEADER, "THREAT_CAMPAIGN_MATCHES_BUDGET_OMISSION"));
        for (SectionOmissionPlan omissionPlan : omissionPlans) {
            int totalTokens = estimateTokens(systemPrompt + "\n---\n" + current);
            if (totalTokens <= budgetProfile.maxInputTokens()) {
                break;
            }
            PromptTransformResult omittedSection = omitNamedSection(
                    current,
                    omissionPlan.header(),
                    omissionPlan.scopeKey(),
                    "Budget enforcement omitted a supporting section after preserving P0/P1 anchors.");
            current = omittedSection.text();
            records.addAll(omittedSection.records());
        }
        return current;
    }

    private PromptTransformResult omitNamedSection(
            String prompt,
            String header,
            String scopeKey,
            String reason) {
        return compactNamedSection(prompt, header, scopeKey, sectionLines -> {
            if (sectionLines.isEmpty()) {
                return SectionTransform.identity(sectionLines);
            }
            return SectionTransform.changed(List.of(), PromptCompressionAction.OMITTED, reason);
        });
    }

    private List<String> retainPriorityLines(
            List<String> sectionLines,
            List<String> requiredPrefixes,
            List<String> priorityPrefixes,
            int maxLines) {
        int detailBudget = Math.max(1, maxLines - 2);
        List<String> compacted = new ArrayList<>();
        compacted.add(sectionLines.get(0));

        Set<String> addedLines = new LinkedHashSet<>();
        for (String prefix : requiredPrefixes) {
            for (int i = 1; i < sectionLines.size(); i++) {
                String line = sectionLines.get(i);
                if (line.isBlank() || !lineStartsWithPrefix(line, prefix) || !addedLines.add(line)) {
                    continue;
                }
                compacted.add(line);
                break;
            }
        }

        int effectiveDetailBudget = Math.max(detailBudget, compacted.size() - 1);
        for (String prefix : priorityPrefixes) {
            if (compacted.size() >= effectiveDetailBudget + 1) {
                break;
            }
            for (int i = 1; i < sectionLines.size(); i++) {
                String line = sectionLines.get(i);
                if (line.isBlank() || !lineStartsWithPrefix(line, prefix) || !addedLines.add(line)) {
                    continue;
                }
                compacted.add(line);
                break;
            }
        }

        for (int i = 1; i < sectionLines.size() && compacted.size() < effectiveDetailBudget + 1; i++) {
            String line = sectionLines.get(i);
            if (line.isBlank() || !addedLines.add(line)) {
                continue;
            }
            compacted.add(line);
        }

        return compacted;
    }

    private boolean lineStartsWithPrefix(String line, String prefix) {
        if (line == null || prefix == null) {
            return false;
        }
        return line.stripLeading().startsWith(prefix);
    }

    private String buildFusedComparableSummary(List<String> docLines) {
        Map<String, Integer> pathCounts = new LinkedHashMap<>();
        Map<String, Integer> hourCounts = new LinkedHashMap<>();
        Map<String, Integer> browserCounts = new LinkedHashMap<>();
        Map<String, Integer> osCounts = new LinkedHashMap<>();
        Map<String, Integer> actionCounts = new LinkedHashMap<>();

        for (String docLine : docLines) {
            collectMetaValue(docLine, "path", pathCounts);
            collectMetaValue(docLine, "hour", hourCounts);
            collectRegexValue(docLine, BROWSER_PATTERN, browserCounts);
            collectRegexValue(docLine, OS_PATTERN, osCounts);
            collectRegexValue(docLine, ACTION_PATTERN, actionCounts);
        }

        List<String> facts = new ArrayList<>();
        facts.add(docLines.size() + " comparable records");
        addTopFact(facts, "Path", pathCounts);
        addTopFact(facts, "Hour", hourCounts);
        addTopFact(facts, "Browser", browserCounts);
        addTopFact(facts, "OS", osCounts);
        addTopFact(facts, "Decision", actionCounts);
        return "FusedComparableSummary: " + String.join(" | ", facts);
    }

    private void addTopFact(List<String> facts, String label, Map<String, Integer> counts) {
        String topValue = topValue(counts);
        if (topValue != null && !topValue.isBlank()) {
            facts.add(label + "=" + topValue);
        }
    }

    private String topValue(Map<String, Integer> counts) {
        String topValue = null;
        int topCount = -1;
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            if (entry.getValue() > topCount) {
                topValue = entry.getKey();
                topCount = entry.getValue();
            }
        }
        return topValue;
    }

    private void collectMetaValue(String docLine, String key, Map<String, Integer> counts) {
        Matcher matcher = DOC_META_PATTERN.matcher(docLine);
        while (matcher.find()) {
            if (!key.equals(matcher.group("key"))) {
                continue;
            }
            increment(counts, matcher.group(2).trim());
        }
    }

    private void collectRegexValue(String docLine, Pattern pattern, Map<String, Integer> counts) {
        Matcher matcher = pattern.matcher(docLine);
        if (matcher.find()) {
            increment(counts, matcher.group(1).trim());
        }
    }

    private void increment(Map<String, Integer> counts, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        counts.merge(value, 1, Integer::sum);
    }

    private int estimateSavedTokens(String rawText, String compactText) {
        return Math.max(0, estimateTokens(rawText) - estimateTokens(compactText));
    }

    private int estimateTokens(String text) {
        if (text == null || text.isBlank()) {
            return 0;
        }
        String modelHint = ESTIMATION_MODEL_HINT.get();
        PromptTokenEstimator estimator = PROMPT_TOKEN_ESTIMATOR_REGISTRY.resolve(modelHint);
        PromptTokenEstimate estimate = estimator.estimate(modelHint, "", text, null);
        return estimate.estimatedTotalTokens();
    }

    private String normalizeLineEndings(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        return text.replace("\r\n", "\n").replace('\r', '\n');
    }

    private String compactWhitespace(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }

        String[] rawLines = text.split("\\n", -1);
        List<String> normalizedLines = new ArrayList<>(rawLines.length);
        int consecutiveBlankLines = 0;
        for (String rawLine : rawLines) {
            String trimmedTrailing = trimTrailingWhitespace(rawLine);
            boolean blank = trimmedTrailing.isBlank();
            if (blank) {
                consecutiveBlankLines++;
                if (consecutiveBlankLines > 1) {
                    continue;
                }
                normalizedLines.add("");
                continue;
            }
            consecutiveBlankLines = 0;
            normalizedLines.add(trimmedTrailing);
        }
        while (!normalizedLines.isEmpty() && normalizedLines.get(normalizedLines.size() - 1).isEmpty()) {
            normalizedLines.remove(normalizedLines.size() - 1);
        }
        return String.join("\n", normalizedLines);
    }

    private String trimTrailingWhitespace(String value) {
        int end = value.length();
        while (end > 0 && Character.isWhitespace(value.charAt(end - 1)) && value.charAt(end - 1) != '\n') {
            end--;
        }
        return value.substring(0, end);
    }

    private boolean rawEquals(String left, String right) {
        return (left == null ? "" : left).equals(right == null ? "" : right);
    }

    private record FactLine(String group, String value) {
    }

    private record SectionOmissionPlan(String header, String scopeKey) {
    }

    private interface SectionCompactor {
        SectionTransform compact(List<String> sectionLines);
    }

    private record SectionTransform(List<String> lines, boolean changed, PromptCompressionAction action, String reason) {
        private SectionTransform {
            lines = lines == null ? List.of() : List.copyOf(lines);
            action = action == null ? PromptCompressionAction.IDENTITY : action;
            reason = reason == null ? "" : reason;
        }

        private static SectionTransform identity(List<String> lines) {
            return new SectionTransform(lines, false, PromptCompressionAction.IDENTITY, "");
        }

        private static SectionTransform changed(List<String> lines, PromptCompressionAction action, String reason) {
            return new SectionTransform(lines, true, action, reason);
        }
    }

    private record PromptTransformResult(String text, List<PromptCompressionRecord> records) {
        private PromptTransformResult {
            text = text == null ? "" : text;
            records = records == null ? List.of() : List.copyOf(records);
        }
    }
}





