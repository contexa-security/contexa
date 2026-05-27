package io.contexa.contexacore.autonomous.context.prompt;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.context.model.ContextEvidenceRecord;
import io.contexa.contexacore.autonomous.context.model.ContextFieldTrustRecord;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;
import io.contexa.contexacore.autonomous.context.policy.CanonicalContextFieldPolicy;
import io.contexa.contexacore.autonomous.context.policy.ContextSemanticBoundaryPolicy;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;

public class PromptContextComposer {

    public static final String PRODUCER_DEVICE_SECTION = "PromptContextComposer.composeDeviceSection";
    public static final String PRODUCER_LOCATION_SECTION = "PromptContextComposer.composeLocationSection";
    public static final String PRODUCER_INTENT_SECTION = "PromptContextComposer.composeIntentSection";
    public static final String PRODUCER_SESSION_SECTION = "PromptContextComposer.composeSessionNarrativeSection";
    public static final String PRODUCER_RESOURCE_SECTION = "PromptContextComposer.composeResourceSection";
    public static final String PRODUCER_ROLE_SCOPE_SECTION = "PromptContextComposer.composeRoleScopeSection";
    public static final String PRODUCER_THREAT_SECTION = "PromptContextComposer.composeReasoningMemorySection";

    private final PromptSlotRenderer slotRenderer;
    private final PromptSlotPlanCache slotPlanCache;

    public PromptContextComposer() {
        this(new PromptSlotRenderer(), new PromptSlotPlanCache());
    }

    PromptContextComposer(PromptSlotRenderer slotRenderer) {
        this(slotRenderer, new PromptSlotPlanCache());
    }

    public PromptContextComposer(PromptSlotRenderer slotRenderer, PromptSlotPlanProvider slotPlanProvider) {
        this(slotRenderer, new PromptSlotPlanCache(slotPlanProvider == null
                ? PromptSlotPlanProvider.unscoped()
                : slotPlanProvider));
    }

    PromptContextComposer(PromptSlotRenderer slotRenderer, PromptSlotPlanCache slotPlanCache) {
        this.slotRenderer = slotRenderer == null ? new PromptSlotRenderer() : slotRenderer;
        this.slotPlanCache = slotPlanCache == null ? new PromptSlotPlanCache() : slotPlanCache;
    }

    public String compose(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        appendSection(section, composeBridgeSection(context));
        appendSection(section, composeCoverageSection(context));
        appendSection(section, composeIdentitySection(context));
        appendSection(section, composeAuthenticationAndAssuranceSection(context));
        appendSection(section, composeDeviceSection(context));
        appendSection(section, composeLocationSection(context));
        appendSection(section, composeIntentSection(context));
        appendSection(section, composeResourceSection(context));
        appendSection(section, composeSessionNarrativeSection(context));
        appendSection(section, composeObservedScopeSection(context));
        appendSection(section, composeWorkProfileSection(context));
        appendSection(section, composeRoleScopeSection(context));
        appendSection(section, composePeerCohortSection(context));
        appendSection(section, composeFrictionSection(context));
        appendSection(section, composeDelegationSection(context));
        appendSection(section, composeReasoningMemorySection(context));
        appendSection(section, composeMissingKnowledgeSection(context));

        return section.isEmpty() ? null : section.toString();
    }

    public String composeBridgeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendBridgeSection(section, context));
    }

    public String composeCoverageSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendCoverageSection(section, context.getCoverage()));
    }

    public String composeIdentitySection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendIdentitySection(section, context));
    }

    public String composeAuthenticationAndAssuranceSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendAuthenticationAndAssuranceSection(section, context.getSession()));
    }

    public String composeDeviceSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendDeviceSection(section, context.getDevice()));
    }

    public String composeLocationSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendLocationSection(section, context.getLocation()));
    }

    public String composeIntentSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendIntentSection(section, context.getIntent()));
    }

    public String composeResourceSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendResourceSection(section, context.getResource()));
    }

    public String composeSessionNarrativeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendSessionNarrativeSection(section, context.getSessionNarrativeProfile()));
    }

    public String composeObservedScopeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendObservedScopeSection(section, context));
    }

    public String composeWorkProfileSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendWorkProfileSection(section, context));
    }

    public String composeContextQualityAndProvenanceSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendContextQualityAndProvenanceSection(section, context.getContextTrustProfiles()));
    }

    public String composeRoleScopeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendRoleScopeSection(section, context));
    }

    public String composePeerCohortSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendPeerCohortSection(section, context));
    }

    public String composeFrictionSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendFrictionSection(section, context.getFrictionProfile()));
    }

    public String composeDelegationSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendDelegationSection(section, context.getDelegation()));
    }

    public String composeReasoningMemorySection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendReasoningMemorySection(section, context.getReasoningMemoryProfile()));
    }

    public String composeMissingKnowledgeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendMissingKnowledgeSection(section, context));
    }

    private String composeSection(CanonicalSecurityContext context, java.util.function.Consumer<StringBuilder> composer) {
        if (context == null) {
            return null;
        }
        StringBuilder section = new StringBuilder();
        composer.accept(section);
        return section.isEmpty() ? null : section.toString();
    }

    private void appendSection(StringBuilder target, String section) {
        if (StringUtils.hasText(section)) {
            target.append(section);
        }
    }

    private void appendBridgeSection(StringBuilder section, CanonicalSecurityContext context) {
        section.append("\n=== BRIDGE RESOLUTION CONTEXT ===\n");
        CanonicalSecurityContext.Bridge bridge = context != null ? context.getBridge() : null;
        if (bridge == null) {
            appendLine(section, "BridgeCompletenessLevel", "UNAVAILABLE");
            appendLine(section, "BridgeCompletenessSummary", "Bridge-derived identity and authorization context was not attached to this request.");
            return;
        }
        appendLine(section, "BridgeCompletenessLevel", bridge.getCoverageLevel());
        appendLine(section, "BridgeCompletenessSummary", bridge.getSummary());
        appendLine(section, "BridgeAuthenticationSource", bridge.getAuthenticationSource());
        appendLine(section, "BridgeAuthorizationSource", bridge.getAuthorizationSource());
        appendLine(section, "BridgeDelegationSource", bridge.getDelegationSource());
        appendList(section, "BridgeMissingContexts", sanitizeBridgeMissingContexts(context, bridge.getMissingContexts()));
        appendList(section, "BridgeRemediationHints", bridge.getRemediationHints());
    }

    private List<String> sanitizeBridgeMissingContexts(
            CanonicalSecurityContext context,
            List<String> missingContexts) {
        if (missingContexts == null || missingContexts.isEmpty()) {
            return missingContexts;
        }
        boolean hasResolvedAuthorizationEffect = context != null
                && context.getAuthorization() != null
                && StringUtils.hasText(context.getAuthorization().getAuthorizationEffect());
        if (!hasResolvedAuthorizationEffect) {
            return missingContexts;
        }
        return missingContexts.stream()
                .filter(StringUtils::hasText)
                .filter(value -> !"AUTHORIZATION_EFFECT".equalsIgnoreCase(value))
                .toList();
    }

    private void appendCoverageSection(StringBuilder section, ContextCoverageReport coverage) {
        if (coverage == null) {
            return;
        }
        section.append("\n=== CONTEXT COVERAGE ===\n");
        section.append("CoverageLevel: ").append(coverage.level()).append("\n");
        section.append("CoverageSummary: ").append(coverage.summary()).append("\n");
        if (!coverage.availableFacts().isEmpty()) {
            section.append("AvailableFacts:\n");
            for (String fact : coverage.availableFacts()) {
                section.append("- ").append(fact).append("\n");
            }
        }
        if (!coverage.missingCriticalFacts().isEmpty()) {
            section.append("MissingCriticalFacts:\n");
            for (String fact : coverage.missingCriticalFacts()) {
                section.append("- ").append(fact).append("\n");
            }
        }
        if (!coverage.remediationHints().isEmpty()) {
            section.append("RemediationHints:\n");
            for (String hint : coverage.remediationHints()) {
                section.append("- ").append(hint).append("\n");
            }
        }
        if (!coverage.confidenceWarnings().isEmpty()) {
            section.append("ConfidenceWarnings:\n");
            for (String warning : coverage.confidenceWarnings()) {
                section.append("- ").append(warning).append("\n");
            }
        }
    }

    private void appendIdentitySection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.Actor actor = context.getActor();
        CanonicalSecurityContext.Authorization authorization = context.getAuthorization();
        if (actor == null && authorization == null) {
            return;
        }

        section.append("\n=== IDENTITY AND ROLE CONTEXT ===\n");
        if (actor != null) {
            appendLine(section, "UserId", actor.getUserId());
            appendLine(section, "ExternalSubjectId", actor.getExternalSubjectId());
            appendLine(section, "OrganizationId", actor.getOrganizationId());
            appendLine(section, "TenantId", actor.getTenantId());
            appendLine(section, "Department", actor.getDepartment());
            appendLine(section, "Position", actor.getPosition());
            appendLine(section, "PrincipalType", actor.getPrincipalType());
            appendLine(section, "BridgeSubjectKey", actor.getBridgeSubjectKey());
            appendList(section, "RoleSet", actor.getRoleSet());
            appendList(section, "AuthoritySet", actor.getAuthoritySet());
        }
        if (authorization != null) {
            appendList(section, "EffectiveRoles", authorization.getEffectiveRoles());
            appendList(section, "EffectivePermissions", authorization.getEffectivePermissions());
            appendList(section, "ScopeTags", authorization.getScopeTags());
            appendLine(section, "AuthorizationEffect", authorization.getAuthorizationEffect());
            appendLine(section, "PolicyId", authorization.getPolicyId());
            appendLine(section, "PolicyVersion", authorization.getPolicyVersion());
            appendLine(section, "PrivilegedFlow", authorization.getPrivileged());
        }
    }

    private void appendAuthenticationAndAssuranceSection(StringBuilder section, CanonicalSecurityContext.Session session) {
        if (session == null) {
            return;
        }

        section.append("\n=== AUTHENTICATION AND ASSURANCE CONTEXT ===\n");
        appendLine(section, "SessionId", session.getSessionId());
        appendLine(section, "ClientIp", session.getClientIp());
        appendLine(section, "UserAgent", session.getUserAgent());
        appendLine(section, "AuthenticationType", session.getAuthenticationType());
        appendLine(section, "AuthenticationAssurance", session.getAuthenticationAssurance());
        appendLine(section, "MfaVerified", session.getMfaVerified());
        appendLine(section, "RecentMfaFailureCount", session.getRecentMfaFailureCount());
        appendLine(section, "LastMfaUsedAt", session.getLastMfaUsedAt());
        appendLineOrExplainedUnknown(section, "FailedLoginAttempts", session.getFailedLoginAttempts(),
                "not available from authentication context; do not assume login failure history");
        appendLine(section, "RecentRequestCount", session.getRecentRequestCount());
        appendLine(section, "RecentChallengeCount", session.getRecentChallengeCount());
        appendLine(section, "RecentBlockCount", session.getRecentBlockCount());
        appendLine(section, "RecentEscalationCount", session.getRecentEscalationCount());
        appendLine(section, "BlockedUser", session.getBlockedUser());
        appendLineOrExplainedUnknown(section, "NewSession", session.getNewSession(),
                "not available from session context; do not assume this is a new session");
        appendLineOrExplainedUnknown(section, "NewUser", session.getNewUser(),
                "not available from identity context; do not assume this is a new user");
        appendLineOrExplainedUnknown(section, "NewDevice", session.getNewDevice(),
                "not available from device context; do not assume this is a new device");
        appendLine(section, "CurrentAccessHour", session.getCurrentAccessHour());
        appendLine(section, "ConcurrentSessions", session.getConcurrentSessions());
        appendLine(section, "PasswordAgeDays", session.getPasswordAgeDays());
    }

    private void appendDeviceSection(StringBuilder section, CanonicalSecurityContext.Device device) {
        if (device == null) {
            return;
        }
        section.append("\n=== DEVICE CONTEXT ===\n");
        appendLine(section, "DeviceOs", device.getOs());
        appendLine(section, "DeviceOsVersion", device.getOsVersion());
        appendLine(section, "DeviceBrowser", device.getBrowser());
        appendLine(section, "DeviceBrowserVersion", device.getBrowserVersion());
        appendLine(section, "DeviceScreenResolution", device.getScreenResolution());
        appendLine(section, "DeviceLanguage", device.getLanguage());
        appendLine(section, "DeviceFingerprintMatch", device.getFingerprintMatch());
    }

    private void appendLocationSection(StringBuilder section, CanonicalSecurityContext.Location location) {
        if (location == null) {
            return;
        }
        section.append("\n=== LOCATION CONTEXT ===\n");
        appendLine(section, "Country", location.getCountry());
        appendLine(section, "City", location.getCity());
        appendLine(section, "IpBand", location.getIpBand());
        appendLine(section, "Asn", location.getAsn());
    }

    private void appendIntentSection(StringBuilder section, CanonicalSecurityContext.Intent intent) {
        section.append("\n=== REQUEST INTENT SIGNAL CONTEXT ===\n");
        if (intent == null) {
            appendLine(section, "IntentSignalStatus",
                    "UNKNOWN - intent signal producer was not available; do not assume bot, referer, language, TLS, header, or travel risk");
            appendLineOrExplainedUnknown(section, "BotUserAgent", null,
                    "not available from intent signal context; do not assume automated client behavior");
            appendLineOrExplainedUnknown(section, "MissingReferer", null,
                    "not available from intent signal context; do not assume referer state");
            appendLineOrExplainedUnknown(section, "LanguageMismatch", null,
                    "not available from intent signal context; do not assume language mismatch");
            appendLineOrExplainedUnknown(section, "TlsFingerprintAltered", null,
                    "not available from intent signal context; do not assume TLS fingerprint alteration");
            appendLineOrExplainedUnknown(section, "AbnormalHeaderOrder", null,
                    "not available from intent signal context; do not assume abnormal header order");
            appendLineOrExplainedUnknown(section, "ImpossibleTravel", null,
                    "not available from intent signal context; do not assume impossible travel");
            return;
        }
        appendLineOrExplainedUnknown(section, "BotUserAgent", intent.getBotUserAgent(),
                "not available from intent signal context; do not assume automated client behavior");
        appendLineOrExplainedUnknown(section, "MissingReferer", intent.getMissingReferer(),
                "not available from intent signal context; do not assume referer state");
        appendLineOrExplainedUnknown(section, "LanguageMismatch", intent.getLanguageMismatch(),
                "not available from intent signal context; do not assume language mismatch");
        appendLineOrExplainedUnknown(section, "TlsFingerprintAltered", intent.getTlsFingerprintAltered(),
                "not available from intent signal context; do not assume TLS fingerprint alteration");
        appendLineOrExplainedUnknown(section, "AbnormalHeaderOrder", intent.getAbnormalHeaderOrder(),
                "not available from intent signal context; do not assume abnormal header order");
        appendLineOrExplainedUnknown(section, "ImpossibleTravel", intent.getImpossibleTravel(),
                "not available from intent signal context; do not assume impossible travel");
    }

    private void appendResourceSection(StringBuilder section, CanonicalSecurityContext.Resource resource) {
        if (resource == null) {
            return;
        }

        section.append("\n=== RESOURCE AND ACTION CONTEXT ===\n");
        appendLine(section, "ResourceId", resource.getResourceId());
        appendLine(section, "RequestPath", resource.getRequestPath());
        appendLine(section, "HttpMethod", resource.getHttpMethod());
        appendLine(section, "ActionFamily", resource.getActionFamily());
        appendLine(section, "ResourceType", resource.getResourceType());
        appendLine(section, "BusinessLabel", resource.getBusinessLabel());
        appendLine(section, "Sensitivity", resource.getSensitivity());
        appendLine(section, "SensitiveResource", resource.getSensitiveResource());
        appendLine(section, "PrivilegedResource", resource.getPrivileged());
        appendLine(section, "ExportSensitive", resource.getExportSensitive());
    }

    private void appendSessionNarrativeSection(StringBuilder section, CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile) {
        if (sessionNarrativeProfile == null) {
            return;
        }

        section.append("\n=== SESSION NARRATIVE CONTEXT ===\n");
        appendLine(section, "SessionNarrativeSummary", sessionNarrativeProfile.getSummary());
        appendLine(section, "SessionAgeMinutes", sessionNarrativeProfile.getSessionAgeMinutes());
        appendLineOrExplainedUnknown(section, "PreviousPath", sessionNarrativeProfile.getPreviousPath(),
                "not available from session narrative context; do not assume a prior path");
        appendLine(section, "PreviousActionFamily", sessionNarrativeProfile.getPreviousActionFamily());
        appendLine(section, "LastRequestIntervalMs", sessionNarrativeProfile.getLastRequestIntervalMs());
        appendList(section, "SessionActionSequence", sessionNarrativeProfile.getSessionActionSequence());
        appendList(section, "SessionProtectableSequence", sessionNarrativeProfile.getSessionProtectableSequence());
        appendLine(section, "BurstPattern", sessionNarrativeProfile.getBurstPattern());
    }

    private void appendObservedScopeSection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.ObservedScope observedScope = context != null ? context.getObservedScope() : null;
        if (observedScope == null) {
            return;
        }

        section.append("\n=== OBSERVED WORK PATTERN CONTEXT ===\n");
        appendLine(section, "ProfileSource", observedScope.getProfileSource());
        appendLine(section, "ObservedScopeSummary", observedScope.getSummary());
        appendLine(section, "RecentProtectableAccessCount", observedScope.getRecentProtectableAccessCount());
        appendLine(section, "RecentDeniedAccessCount", observedScope.getRecentDeniedAccessCount());
        appendLine(section, "RecentSensitiveAccessCount", observedScope.getRecentSensitiveAccessCount());
        appendList(section, "FrequentResources", observedScope.getFrequentResources());
        appendList(section, "FrequentActionFamilies", observedScope.getFrequentActionFamilies());
        appendComparisonEvidence(
                section,
                "CurrentResourcePresentInObservedHistory",
                resolveCurrentResourceValue(context),
                observedScope.getFrequentResources(),
                observedScope.getRareCurrentResource());
        appendComparisonEvidence(
                section,
                "CurrentActionFamilyPresentInObservedHistory",
                resolveCurrentActionFamily(context),
                observedScope.getFrequentActionFamilies(),
                observedScope.getRareCurrentActionFamily());
    }

    private void appendWorkProfileSection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.WorkProfile workProfile = context != null ? context.getWorkProfile() : null;
        if (workProfile == null) {
            return;
        }

        section.append("\n=== PERSONAL WORK PROFILE ===\n");
        appendEvidenceState(section, "WorkProfileEvidenceState",
                CanonicalContextFieldPolicy.hasWorkProfileTrustAssessment(context),
                CanonicalContextFieldPolicy.hasWorkProfile(context),
                CanonicalContextFieldPolicy.hasProvisionalWorkProfile(context));
        appendLine(section, "WorkProfileSummary", workProfile.getSummary());
        appendList(section, "FrequentProtectableResources", workProfile.getFrequentProtectableResources());
        appendList(section, "FrequentActionFamilies", workProfile.getFrequentActionFamilies());
        appendList(section, "FrequentSensitiveResourceCategories", workProfile.getFrequentSensitiveResourceCategories());
        appendList(section, "ProtectableResourceHeatmap", workProfile.getProtectableResourceHeatmap());
        appendIntegerList(section, "NormalAccessHours", workProfile.getNormalAccessHours());
        appendIntegerList(section, "NormalAccessDays", workProfile.getNormalAccessDays());
        appendLine(section, "NormalRequestRate", workProfile.getNormalRequestRate());
        appendLine(section, "NormalSessionLengthMinutes", workProfile.getNormalSessionLengthMinutes());
        appendLine(section, "NormalReadWriteExportRatio", workProfile.getNormalReadWriteExportRatio());
        appendLine(section, "NormalPrivilegedActionFrequency", workProfile.getNormalPrivilegedActionFrequency());
        appendLine(section, "ProtectableInvocationDensity", workProfile.getProtectableInvocationDensity());
        appendLine(section, "SeasonalBusinessProfile", workProfile.getSeasonalBusinessProfile());
        appendList(section, "LongTailLegitimateTasks", workProfile.getLongTailLegitimateTasks());
    }

    private void appendContextQualityAndProvenanceSection(StringBuilder section, List<ContextTrustProfile> trustProfiles) {
        if (trustProfiles == null || trustProfiles.isEmpty()) {
            return;
        }

        section.append("\n=== CONTEXT QUALITY AND PROVENANCE ===\n");
        for (ContextTrustProfile trustProfile : trustProfiles) {
            if (trustProfile == null) {
                continue;
            }
            appendLine(section, "TrustProfileKey", trustProfile.getProfileKey());
            appendLine(section, "TrustCollectorId", trustProfile.getCollectorId());
            appendLine(section, "TrustProfileSummary", trustProfile.getSummary());
            appendLine(section, "TrustProvenanceSummary", trustProfile.getProvenanceSummary());
            appendList(section, "TrustScopeLimitations", trustProfile.getScopeLimitations());
            appendList(section, "TrustQualityWarnings", trustProfile.getQualityWarnings());
            if (!trustProfile.getFieldRecords().isEmpty()) {
                section.append("TrustFieldAudits:\n");
                for (ContextFieldTrustRecord fieldRecord : trustProfile.getFieldRecords()) {
                    if (fieldRecord == null) {
                        continue;
                    }
                    section.append("- ")
                            .append(fieldRecord.getFieldPath())
                            .append(" | observations=")
                            .append(fieldRecord.getObservationCount())
                            .append(" | days=")
                            .append(fieldRecord.getDaysCovered())
                            .append(" | fallback=")
                            .append(formatPercent(fieldRecord.getFallbackRate()))
                            .append(" | unknown=")
                            .append(formatPercent(fieldRecord.getUnknownRate()))
                            .append(" | provenance=")
                            .append(fieldRecord.getProvenanceSummary())
                            .append(" | evidenceState=")
                            .append(describeFieldEvidenceState(fieldRecord))
                            .append("\n");
                }
            }
            if (!trustProfile.getEvidenceRecords().isEmpty()) {
                section.append("TrustEvidence:\n");
                for (ContextEvidenceRecord evidenceRecord : trustProfile.getEvidenceRecords()) {
                    if (evidenceRecord == null) {
                        continue;
                    }
                    section.append("- ")
                            .append(evidenceRecord.getEvidenceId())
                            .append(" | ")
                            .append(evidenceRecord.getSummary())
                            .append("\n");
                }
            }
        }
    }

    private void appendRoleScopeSection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.RoleScopeProfile roleScopeProfile = context != null ? context.getRoleScopeProfile() : null;
        if (roleScopeProfile == null) {
            return;
        }
        CanonicalSecurityContext.Resource resource = context != null ? context.getResource() : null;
        String currentResourceFamily = firstText(
                roleScopeProfile.getCurrentResourceFamily(),
                SecuritySemanticNormalizer.normalizeResourceFamily(
                        resource != null ? resource.getResourceType() : null,
                        resource != null ? resource.getSensitivity() : null));
        String currentActionFamily = firstText(
                roleScopeProfile.getCurrentActionFamily(),
                SecuritySemanticNormalizer.normalizeActionFamily(
                        resource != null ? resource.getActionFamily() : null,
                        resource != null ? resource.getHttpMethod() : null));

        section.append("\n=== ROLE AND WORK SCOPE CONTEXT ===\n");
        appendEvidenceState(section, "RoleScopeEvidenceState",
                CanonicalContextFieldPolicy.hasRoleScopeTrustAssessment(context),
                CanonicalContextFieldPolicy.hasRoleScopeProfile(context),
                CanonicalContextFieldPolicy.hasProvisionalRoleScopeProfile(context));
        appendLine(section, "RoleScopeSummary", roleScopeProfile.getSummary());
        appendLine(section, "CurrentResourceFamily", currentResourceFamily);
        appendLine(section, "CurrentActionFamily", currentActionFamily);
        appendList(section, "ExpectedResourceFamilies", roleScopeProfile.getExpectedResourceFamilies());
        appendList(section, "ExpectedActionFamilies", roleScopeProfile.getExpectedActionFamilies());
        appendList(section, "ForbiddenResourceFamilies", roleScopeProfile.getForbiddenResourceFamilies());
        appendList(section, "ForbiddenActionFamilies", roleScopeProfile.getForbiddenActionFamilies());
        appendList(section, "NormalApprovalPatterns", roleScopeProfile.getNormalApprovalPatterns());
        appendList(section, "NormalEscalationPatterns", roleScopeProfile.getNormalEscalationPatterns());
        if (roleScopeProfile.getRecentPermissionChanges() == null || roleScopeProfile.getRecentPermissionChanges().isEmpty()) {
            appendLine(section, "RecentPermissionChanges", "UNKNOWN");
        } else {
            appendList(section, "RecentPermissionChanges", roleScopeProfile.getRecentPermissionChanges());
        }
        Boolean currentResourcePresentInExpectedRoleScope = !roleScopeProfile.getExpectedResourceFamilies().isEmpty()
                ? ContextSemanticBoundaryPolicy.comparisonIncludesCurrent(
                currentResourceFamily,
                roleScopeProfile.getExpectedResourceFamilies())
                : null;
        Boolean currentResourcePresentInDeniedRoleScope = !roleScopeProfile.getForbiddenResourceFamilies().isEmpty()
                ? ContextSemanticBoundaryPolicy.comparisonIncludesCurrent(
                currentResourceFamily,
                roleScopeProfile.getForbiddenResourceFamilies())
                : null;
        Boolean currentActionPresentInExpectedRoleScope = !roleScopeProfile.getExpectedActionFamilies().isEmpty()
                ? ContextSemanticBoundaryPolicy.comparisonIncludesCurrent(
                currentActionFamily,
                roleScopeProfile.getExpectedActionFamilies())
                : null;
        Boolean currentActionPresentInDeniedRoleScope = !roleScopeProfile.getForbiddenActionFamilies().isEmpty()
                ? ContextSemanticBoundaryPolicy.comparisonIncludesCurrent(
                currentActionFamily,
                roleScopeProfile.getForbiddenActionFamilies())
                : null;
        List<String> roleScopeDeltas = new ArrayList<>();
        if (Boolean.FALSE.equals(currentResourcePresentInExpectedRoleScope)) {
            roleScopeDeltas.add("resource family outside expected role scope");
        }
        if (Boolean.TRUE.equals(currentResourcePresentInDeniedRoleScope)) {
            roleScopeDeltas.add("resource family present in denied role scope");
        }
        if (Boolean.FALSE.equals(currentActionPresentInExpectedRoleScope)) {
            roleScopeDeltas.add("action family outside expected role scope");
        }
        if (Boolean.TRUE.equals(currentActionPresentInDeniedRoleScope)) {
            roleScopeDeltas.add("action family present in denied role scope");
        }
        boolean hasDirectScopeEvidence = !roleScopeProfile.getExpectedResourceFamilies().isEmpty()
                || !roleScopeProfile.getExpectedActionFamilies().isEmpty()
                || !roleScopeProfile.getForbiddenResourceFamilies().isEmpty()
                || !roleScopeProfile.getForbiddenActionFamilies().isEmpty();
        boolean unreliableRoleScope = CanonicalContextFieldPolicy.hasProvisionalRoleScopeProfile(context)
                || (!CanonicalContextFieldPolicy.hasRoleScopeTrustAssessment(context) && !hasDirectScopeEvidence);
        if (roleScopeDeltas.isEmpty() && unreliableRoleScope) {
            appendLine(section, "RoleScopeDeltaCount", "UNKNOWN");
            appendLine(section, "StrongestRoleScopeDelta", "insufficient scope evidence");
            appendLine(section, "RoleScopeDeltaSummary", "current-vs-scope comparison not reliable");
        } else {
            appendLine(section, "RoleScopeDeltaCount", roleScopeDeltas.size());
            appendLine(section, "StrongestRoleScopeDelta",
                    roleScopeDeltas.isEmpty()
                            ? "none"
                            : roleScopeDeltas.getFirst());
            appendLine(section, "RoleScopeDeltaSummary",
                    roleScopeDeltas.isEmpty()
                            ? "no direct current-vs-scope mismatch detected"
                            : String.join(" | ", roleScopeDeltas));
        }
        appendComparisonEvidence(
                section,
                "CurrentResourceFamilyPresentInExpectedRoleScope",
                currentResourceFamily,
                roleScopeProfile.getExpectedResourceFamilies(),
                currentResourcePresentInExpectedRoleScope);
        appendComparisonEvidence(
                section,
                "CurrentResourceFamilyPresentInDeniedRoleScope",
                currentResourceFamily,
                roleScopeProfile.getForbiddenResourceFamilies(),
                currentResourcePresentInDeniedRoleScope);
        appendComparisonEvidence(
                section,
                "CurrentActionFamilyPresentInExpectedRoleScope",
                currentActionFamily,
                roleScopeProfile.getExpectedActionFamilies(),
                currentActionPresentInExpectedRoleScope);
        appendComparisonEvidence(
                section,
                "CurrentActionFamilyPresentInDeniedRoleScope",
                currentActionFamily,
                roleScopeProfile.getForbiddenActionFamilies(),
                currentActionPresentInDeniedRoleScope);
        appendLine(section, "TemporaryElevation", roleScopeProfile.getTemporaryElevation());
        appendLine(section, "TemporaryElevationReason", roleScopeProfile.getTemporaryElevationReason());
        appendLine(section, "ElevatedPrivilegeWindowActive", roleScopeProfile.getElevatedPrivilegeWindowActive());
        appendLine(section, "ElevationWindowSummary", roleScopeProfile.getElevationWindowSummary());
    }

    private void appendPeerCohortSection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.PeerCohortProfile peerCohortProfile = context != null ? context.getPeerCohortProfile() : null;
        if (peerCohortProfile == null) {
            return;
        }

        section.append("\n=== PEER COHORT DELTA ===\n");
        appendLine(section, "PeerCohortId", peerCohortProfile.getCohortId());
        appendLine(section, "PeerCohortSummary", peerCohortProfile.getSummary());
        appendList(section, "CohortPreferredResources", peerCohortProfile.getPreferredResources());
        appendList(section, "CohortPreferredActionFamilies", peerCohortProfile.getPreferredActionFamilies());
        appendLine(section, "CohortNormalProtectableFrequencyBand", peerCohortProfile.getNormalProtectableFrequencyBand());
        appendLine(section, "CohortNormalSensitivityBand", peerCohortProfile.getNormalSensitivityBand());
        appendComparisonEvidence(
                section,
                "CurrentResourcePresentInPeerPreferredResources",
                resolveCurrentResourceValue(context),
                peerCohortProfile.getPreferredResources(),
                !peerCohortProfile.getPreferredResources().isEmpty()
                        ? containsIgnoreCase(peerCohortProfile.getPreferredResources(), resolveCurrentResourceValue(context))
                        : null);
        appendComparisonEvidence(
                section,
                "CurrentActionFamilyPresentInPeerPreferredActions",
                resolveCurrentActionFamily(context),
                peerCohortProfile.getPreferredActionFamilies(),
                !peerCohortProfile.getPreferredActionFamilies().isEmpty()
                        ? containsIgnoreCase(peerCohortProfile.getPreferredActionFamilies(), resolveCurrentActionFamily(context))
                        : null);
    }

    private void appendFrictionSection(StringBuilder section, CanonicalSecurityContext.FrictionProfile frictionProfile) {
        section.append("\n=== FRICTION AND APPROVAL HISTORY ===\n");
        if (frictionProfile == null) {
            appendLine(section, "ApprovalRequired", "UNKNOWN");
            appendLine(section, "ApprovalGranted", "UNKNOWN");
            appendLine(section, "ApprovalMissing", "UNKNOWN");
            appendLine(section, "ApprovalStatus", "UNKNOWN");
            return;
        }
        appendLine(section, "FrictionSummary", frictionProfile.getSummary());
        appendLine(section, "RecentChallengeCount", frictionProfile.getRecentChallengeCount());
        appendLine(section, "RecentBlockCount", frictionProfile.getRecentBlockCount());
        appendLine(section, "RecentEscalationCount", frictionProfile.getRecentEscalationCount());
        appendLineOrUnknown(section, "ApprovalRequired", frictionProfile.getApprovalRequired());
        appendLineOrUnknown(section, "ApprovalGranted", frictionProfile.getApprovalGranted());
        appendLineOrUnknown(section, "ApprovalMissing", frictionProfile.getApprovalMissing());
        appendLineOrUnknown(section, "ApprovalStatus", frictionProfile.getApprovalStatus());
        appendList(section, "ApprovalLineage", frictionProfile.getApprovalLineage());
        appendList(section, "PendingApproverRoles", frictionProfile.getPendingApproverRoles());
        appendLine(section, "ApprovalTicketId", frictionProfile.getApprovalTicketId());
        appendLine(section, "ApprovalDecisionAgeMinutes", frictionProfile.getApprovalDecisionAgeMinutes());
        appendLine(section, "BreakGlass", frictionProfile.getBreakGlass());
        appendLine(section, "RecentDeniedAccessCount", frictionProfile.getRecentDeniedAccessCount());
        appendLine(section, "BlockedUser", frictionProfile.getBlockedUser());
    }

    private void appendDelegationSection(StringBuilder section, CanonicalSecurityContext.Delegation delegation) {
        section.append("\n=== DELEGATED OBJECTIVE CONTEXT ===\n");
        if (delegation == null || !hasDelegationData(delegation)) {
            appendLine(section, "Delegated", "UNKNOWN");
            appendLine(section, "ObjectiveFamily", "UNKNOWN");
            appendLine(section, "ObjectiveSummary", "UNKNOWN");
            appendLine(section, "ObjectiveAlignmentEvidence", "UNKNOWN");
            return;
        }
        if (Boolean.FALSE.equals(delegation.getDelegated())) {
            appendLine(section, "Delegated", false);
            appendLine(section, "AgentId", delegation.getAgentId());
            appendLine(section, "ObjectiveId", delegation.getObjectiveId());
            appendLine(section, "ObjectiveFamily", "NOT_APPLICABLE");
            appendLine(section, "ObjectiveSummary", "NOT_APPLICABLE");
            appendList(section, "AllowedOperations", delegation.getAllowedOperations());
            appendList(section, "AllowedResources", delegation.getAllowedResources());
            appendLine(section, "ApprovalRequired", delegation.getApprovalRequired());
            appendLine(section, "PrivilegedExportAllowed", delegation.getPrivilegedExportAllowed());
            appendLine(section, "ContainmentOnly", delegation.getContainmentOnly());
            appendLine(section, "ObjectiveAlignmentEvidence",
                    firstText(delegation.getObjectiveDriftSummary(), "NOT_APPLICABLE"));
            return;
        }
        appendLineOrUnknown(section, "Delegated", delegation.getDelegated());
        appendLine(section, "AgentId", delegation.getAgentId());
        appendLine(section, "ObjectiveId", delegation.getObjectiveId());
        appendLineOrUnknown(section, "ObjectiveFamily", delegation.getObjectiveFamily());
        appendLineOrUnknown(section, "ObjectiveSummary", delegation.getObjectiveSummary());
        appendList(section, "AllowedOperations", delegation.getAllowedOperations());
        appendList(section, "AllowedResources", delegation.getAllowedResources());
        appendLine(section, "ApprovalRequired", delegation.getApprovalRequired());
        appendLine(section, "PrivilegedExportAllowed", delegation.getPrivilegedExportAllowed());
        appendLine(section, "ContainmentOnly", delegation.getContainmentOnly());
        appendLineOrUnknown(section, "ObjectiveAlignmentEvidence", delegation.getObjectiveDriftSummary());
    }

    private void appendReasoningMemorySection(StringBuilder section, CanonicalSecurityContext.ReasoningMemoryProfile reasoningMemoryProfile) {
        if (reasoningMemoryProfile == null) {
            return;
        }

        section.append("\n=== OUTCOME AND REASONING MEMORY ===\n");
        appendLine(section, "ReasoningMemorySummary", reasoningMemoryProfile.getSummary());
        appendLine(section, "ReinforcedCaseCount", reasoningMemoryProfile.getReinforcedCaseCount());
        appendLine(section, "HardNegativeCaseCount", reasoningMemoryProfile.getHardNegativeCaseCount());
        appendLine(section, "FalseNegativeCaseCount", reasoningMemoryProfile.getFalseNegativeCaseCount());
        appendLine(section, "KnowledgeAssistedCaseCount", reasoningMemoryProfile.getKnowledgeAssistedCaseCount());
        appendLine(section, "ObjectiveAwareReasoningMemory", reasoningMemoryProfile.getObjectiveAwareReasoningMemory());
        appendLine(section, "RetentionTier", reasoningMemoryProfile.getRetentionTier());
        appendLine(section, "RecallPriority", reasoningMemoryProfile.getRecallPriority());
        appendLine(section, "FreshnessState", reasoningMemoryProfile.getFreshnessState());
        appendLine(section, "ReasoningState", reasoningMemoryProfile.getReasoningState());
        appendLine(section, "CohortPreference", reasoningMemoryProfile.getCohortPreference());
        appendLine(section, "MemoryRiskProfile", reasoningMemoryProfile.getMemoryRiskProfile());
        appendLine(section, "RetrievalWeight", reasoningMemoryProfile.getRetrievalWeight());
        appendList(section, "MatchedSignalKeys", reasoningMemoryProfile.getMatchedSignalKeys());
        appendList(section, "ObjectiveFamilies", reasoningMemoryProfile.getObjectiveFamilies());
        appendList(section, "MemoryGuardrails", reasoningMemoryProfile.getMemoryGuardrails());
        appendList(section, "XaiLinkedFacts", reasoningMemoryProfile.getXaiLinkedFacts());
        appendList(section, "ReasoningFacts", reasoningMemoryProfile.getReasoningFacts());
        appendLine(section, "CrossTenantObjectiveMisusePackSummary", reasoningMemoryProfile.getCrossTenantObjectiveMisusePackSummary());
        appendList(section, "CrossTenantObjectiveMisuseFacts", reasoningMemoryProfile.getCrossTenantObjectiveMisuseFacts());
    }

    private void appendMissingKnowledgeSection(StringBuilder section, CanonicalSecurityContext context) {
        ContextCoverageReport coverage = context.getCoverage();
        List<ContextTrustProfile> trustProfiles = context.getContextTrustProfiles();
        if (!hasMissingKnowledge(coverage, trustProfiles)) {
            return;
        }

        section.append("\n=== EXPLICIT MISSING KNOWLEDGE ===\n");
        boolean hasResolvedAuthorizationEffect = context != null
                && context.getAuthorization() != null
                && StringUtils.hasText(context.getAuthorization().getAuthorizationEffect());
        if (coverage != null) {
            for (String fact : coverage.missingCriticalFacts()) {
                if (hasResolvedAuthorizationEffect
                        && "Bridge missing context: AUTHORIZATION_EFFECT.".equals(fact)) {
                    continue;
                }
                section.append("- ").append(fact).append("\n");
            }
        }
        if (trustProfiles == null || trustProfiles.isEmpty()) {
            return;
        }
        for (ContextTrustProfile trustProfile : trustProfiles) {
            if (trustProfile == null || !hasTrustGating(trustProfile)) {
                continue;
            }
            section.append("- ContextEvidenceLimitation: ")
                    .append(trustProfile.getProfileKey())
                    .append(" | collector=")
                    .append(trustProfile.getCollectorId())
                    .append(" | provenance=")
                    .append(trustProfile.getProvenanceSummary())
                    .append(" | evidenceState=")
                    .append(describeProfileEvidenceState(trustProfile))
                    .append("\n");
            for (String limitation : trustProfile.getScopeLimitations()) {
                section.append("- ContextTrustLimitation: ")
                        .append(trustProfile.getProfileKey())
                        .append(" | ")
                        .append(limitation)
                        .append("\n");
            }
            for (String warning : trustProfile.getQualityWarnings()) {
                section.append("- ContextTrustWarning: ")
                        .append(trustProfile.getProfileKey())
                        .append(" | ")
                        .append(warning)
                        .append("\n");
            }
            for (ContextFieldTrustRecord fieldRecord : trustProfile.getFieldRecords()) {
                if (fieldRecord == null || !ContextSemanticBoundaryPolicy.requiresEvidenceCaution(fieldRecord)) {
                    continue;
                }
                section.append("- ContextFieldCoverage: ")
                        .append(fieldRecord.getFieldPath())
                        .append(" | observations=")
                        .append(fieldRecord.getObservationCount())
                        .append(" | days=")
                        .append(fieldRecord.getDaysCovered())
                        .append(" | fallback=")
                        .append(formatPercent(fieldRecord.getFallbackRate()))
                        .append(" | unknown=")
                        .append(formatPercent(fieldRecord.getUnknownRate()))
                        .append(" | provenance=")
                        .append(fieldRecord.getProvenanceSummary())
                        .append("\n");
                section.append("- ContextFieldLimitation: ")
                        .append(fieldRecord.getFieldPath())
                        .append(" | ")
                        .append(describeFieldEvidenceLimitation(fieldRecord))
                        .append("\n");
            }
        }
    }

    private boolean hasMissingKnowledge(ContextCoverageReport coverage, List<ContextTrustProfile> trustProfiles) {
        boolean hasCoverageGap = coverage != null
                && (!coverage.missingCriticalFacts().isEmpty()
                || !coverage.remediationHints().isEmpty()
                || !coverage.confidenceWarnings().isEmpty());
        if (hasCoverageGap) {
            return true;
        }
        if (trustProfiles == null || trustProfiles.isEmpty()) {
            return false;
        }
        for (ContextTrustProfile trustProfile : trustProfiles) {
            if (trustProfile != null && hasTrustGating(trustProfile)) {
                return true;
            }
        }
        return false;
    }

    private void appendEvidenceState(
            StringBuilder section,
            String label,
            boolean hasTrustAssessment,
            boolean trusted,
            boolean provisional) {
        if (!hasTrustAssessment) {
            return;
        }
        if (trusted) {
            appendLine(section, label, "TRUSTED");
            return;
        }
        if (provisional) {
            appendLine(section, label, "PROVISIONAL");
        }
    }

    private boolean hasTrustGating(ContextTrustProfile trustProfile) {
        return ContextSemanticBoundaryPolicy.requiresEvidenceCaution(trustProfile)
                || !trustProfile.getScopeLimitations().isEmpty()
                || !trustProfile.getQualityWarnings().isEmpty()
                || trustProfile.getFieldRecords().stream()
                .anyMatch(fieldRecord -> fieldRecord != null && ContextSemanticBoundaryPolicy.requiresEvidenceCaution(fieldRecord));
    }

    private boolean hasDelegationData(CanonicalSecurityContext.Delegation delegation) {
        return delegation.getDelegated() != null
                || StringUtils.hasText(delegation.getAgentId())
                || StringUtils.hasText(delegation.getObjectiveId())
                || StringUtils.hasText(delegation.getObjectiveFamily())
                || StringUtils.hasText(delegation.getObjectiveSummary())
                || !delegation.getAllowedOperations().isEmpty()
                || !delegation.getAllowedResources().isEmpty()
                || delegation.getApprovalRequired() != null
                || delegation.getPrivilegedExportAllowed() != null
                || delegation.getContainmentOnly() != null
                || delegation.getObjectiveDrift() != null
                || StringUtils.hasText(delegation.getObjectiveDriftSummary());
    }

    private void appendList(StringBuilder section, String label, List<String> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        appendSlot(section, label, values, String.join(", ", values));
    }

    private void appendIntegerList(StringBuilder section, String label, List<Integer> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        appendSlot(section, label, values, values.stream().map(String::valueOf).toList().toString());
    }

    private void appendLine(StringBuilder section, String label, Object value) {
        if (value == null) {
            return;
        }
        String text = value.toString();
        if (!StringUtils.hasText(text)) {
            return;
        }
        appendSlot(section, label, value, text);
    }

    private void appendSlot(StringBuilder section, String label, Object sourceValue, String renderedValue) {
        PromptSlotPlan plan = slotPlanCache.planFor(currentSectionKey(section), label);
        String rendered = slotRenderer.renderLine(plan.bind(sourceValue, renderedValue, null));
        if (StringUtils.hasText(rendered)) {
            section.append(rendered);
        }
    }

    private String currentSectionKey(StringBuilder section) {
        if (section == null || section.isEmpty()) {
            return null;
        }
        String current = section.toString();
        int markerStart = current.lastIndexOf("\n=== ");
        if (markerStart < 0) {
            markerStart = current.lastIndexOf("=== ");
        }
        if (markerStart < 0) {
            return null;
        }
        int titleStart = current.indexOf("=== ", markerStart);
        if (titleStart < 0) {
            return null;
        }
        titleStart += 4;
        int titleEnd = current.indexOf(" ===", titleStart);
        if (titleEnd <= titleStart) {
            return null;
        }
        String sectionKey = current.substring(titleStart, titleEnd).trim();
        return StringUtils.hasText(sectionKey) ? sectionKey : null;
    }

    private void appendLineOrUnknown(StringBuilder section, String label, Object value) {
        if (value == null) {
            appendLine(section, label, "UNKNOWN");
            return;
        }
        String text = value.toString();
        if (!StringUtils.hasText(text)) {
            appendLine(section, label, "UNKNOWN");
            return;
        }
        appendLine(section, label, text);
    }

    private void appendLineOrExplainedUnknown(StringBuilder section, String label, Object value, String reason) {
        if (value == null) {
            appendLine(section, label, "UNKNOWN - " + reason);
            return;
        }
        String text = value.toString();
        if (!StringUtils.hasText(text)) {
            appendLine(section, label, "UNKNOWN - " + reason);
            return;
        }
        appendLine(section, label, text);
    }

    private String formatPercent(Double value) {
        if (value == null) {
            return "0%";
        }
        return String.format(java.util.Locale.ROOT, "%.0f%%", value * 100.0d);
    }

    private void appendComparisonEvidence(
            StringBuilder section,
            String label,
            String currentValue,
            List<String> comparedValues,
            Boolean present) {
        if (!StringUtils.hasText(currentValue)) {
            return;
        }
        if (comparedValues == null || comparedValues.isEmpty() || present == null) {
            appendLine(section, label, "UNKNOWN");
            return;
        }
        appendLine(section, label, present);
    }

    private String resolveCurrentResourceValue(CanonicalSecurityContext context) {
        if (context == null || context.getResource() == null) {
            return null;
        }
        return firstText(context.getResource().getResourceId(), context.getResource().getRequestPath(), context.getResource().getResourceType());
    }

    private String resolveCurrentActionFamily(CanonicalSecurityContext context) {
        if (context == null || context.getResource() == null) {
            return null;
        }
        return firstText(context.getResource().getActionFamily(), context.getResource().getHttpMethod());
    }

    private String describeProfileEvidenceState(ContextTrustProfile trustProfile) {
        return ContextSemanticBoundaryPolicy.describeProfileEvidenceState(trustProfile);
    }

    private String describeFieldEvidenceState(ContextFieldTrustRecord fieldRecord) {
        return ContextSemanticBoundaryPolicy.describeFieldEvidenceState(fieldRecord);
    }

    private String describeFieldEvidenceLimitation(ContextFieldTrustRecord fieldRecord) {
        List<String> factors = new ArrayList<>();
        if (ContextSemanticBoundaryPolicy.hasThinCoverage(fieldRecord)) {
            factors.add("evidence count or time coverage is thin");
        }
        if (ContextSemanticBoundaryPolicy.hasFallbackHeavyCoverage(fieldRecord)) {
            factors.add("value derivation depends on fallback signals");
        }
        if (ContextSemanticBoundaryPolicy.hasUnknownHeavyCoverage(fieldRecord)) {
            factors.add("unknown values remain high");
        }
        if (factors.isEmpty()) {
            factors.add("evidence coverage is still partial");
        }
        return String.join("; ", factors);
    }

    private boolean containsIgnoreCase(List<String> values, String target) {
        if (!StringUtils.hasText(target) || values == null || values.isEmpty()) {
            return false;
        }
        for (String value : values) {
            if (StringUtils.hasText(value) && target.equalsIgnoreCase(value.trim())) {
                return true;
            }
        }
        return false;
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }
}
