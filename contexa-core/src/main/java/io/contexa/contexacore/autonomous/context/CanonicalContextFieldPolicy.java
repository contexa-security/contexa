package io.contexa.contexacore.autonomous.context;

import org.springframework.util.StringUtils;

public final class CanonicalContextFieldPolicy {

    private CanonicalContextFieldPolicy() {
    }

    public static boolean hasActorIdentity(CanonicalSecurityContext context) {
        return context != null
                && context.getActor() != null
                && StringUtils.hasText(context.getActor().getUserId());
    }

    public static boolean hasSessionIdentity(CanonicalSecurityContext context) {
        return context != null
                && context.getSession() != null
                && StringUtils.hasText(context.getSession().getSessionId());
    }

    public static boolean hasEffectiveRoles(CanonicalSecurityContext context) {
        return context != null
                && context.getAuthorization() != null
                && !context.getAuthorization().getEffectiveRoles().isEmpty();
    }

    public static boolean hasAuthorizationScope(CanonicalSecurityContext context) {
        return context != null
                && context.getAuthorization() != null
                && (!context.getAuthorization().getEffectivePermissions().isEmpty()
                || !context.getAuthorization().getScopeTags().isEmpty());
    }

    public static boolean hasResourceIdentity(CanonicalSecurityContext context) {
        return context != null
                && context.getResource() != null
                && StringUtils.hasText(context.getResource().getResourceId());
    }

    public static boolean hasResourceBusinessLabel(CanonicalSecurityContext context) {
        return context != null
                && context.getResource() != null
                && StringUtils.hasText(context.getResource().getBusinessLabel());
    }

    public static boolean hasResourceSensitivity(CanonicalSecurityContext context) {
        return context != null
                && context.getResource() != null
                && StringUtils.hasText(context.getResource().getSensitivity());
    }

    public static boolean hasResourceBusinessSemantics(CanonicalSecurityContext context) {
        return hasResourceBusinessLabel(context) && hasResourceSensitivity(context);
    }

    public static boolean hasMfaState(CanonicalSecurityContext context) {
        return context != null
                && context.getSession() != null
                && context.getSession().getMfaVerified() != null;
    }

    public static boolean hasObservedScope(CanonicalSecurityContext context) {
        return context != null
                && context.getObservedScope() != null
                && (StringUtils.hasText(context.getObservedScope().getSummary())
                || !context.getObservedScope().getFrequentResources().isEmpty()
                || !context.getObservedScope().getFrequentActionFamilies().isEmpty()
                || context.getObservedScope().getRecentProtectableAccessCount() != null);
    }

    public static boolean hasSessionNarrativeProfile(CanonicalSecurityContext context) {
        return context != null
                && context.getSessionNarrativeProfile() != null
                && (StringUtils.hasText(context.getSessionNarrativeProfile().getSummary())
                || context.getSessionNarrativeProfile().getSessionAgeMinutes() != null
                || StringUtils.hasText(context.getSessionNarrativeProfile().getPreviousPath())
                || StringUtils.hasText(context.getSessionNarrativeProfile().getPreviousActionFamily())
                || context.getSessionNarrativeProfile().getLastRequestIntervalMs() != null
                || !context.getSessionNarrativeProfile().getSessionActionSequence().isEmpty()
                || !context.getSessionNarrativeProfile().getSessionProtectableSequence().isEmpty()
                || context.getSessionNarrativeProfile().getBurstPattern() != null);
    }

    public static boolean hasWorkProfile(CanonicalSecurityContext context) {
        ContextTrustProfile trustProfile = findTrustProfile(context, "PERSONAL_WORK_PROFILE");
        if (trustProfile != null && (trustProfile.getOverallQualityGrade() == null || !trustProfile.getOverallQualityGrade().supportsReasoning())) {
            return false;
        }
        return context != null
                && context.getWorkProfile() != null
                && (StringUtils.hasText(context.getWorkProfile().getSummary())
                || !context.getWorkProfile().getFrequentProtectableResources().isEmpty()
                || !context.getWorkProfile().getFrequentActionFamilies().isEmpty()
                || !context.getWorkProfile().getProtectableResourceHeatmap().isEmpty()
                || !context.getWorkProfile().getNormalAccessHours().isEmpty()
                || context.getWorkProfile().getNormalRequestRate() != null
                || context.getWorkProfile().getProtectableInvocationDensity() != null
                || StringUtils.hasText(context.getWorkProfile().getSeasonalBusinessProfile())
                || !context.getWorkProfile().getLongTailLegitimateTasks().isEmpty());
    }

    private static ContextTrustProfile findTrustProfile(CanonicalSecurityContext context, String profileKey) {
        if (context == null || context.getContextTrustProfiles() == null || context.getContextTrustProfiles().isEmpty()) {
            return null;
        }
        for (ContextTrustProfile trustProfile : context.getContextTrustProfiles()) {
            if (trustProfile != null && profileKey.equalsIgnoreCase(trustProfile.getProfileKey())) {
                return trustProfile;
            }
        }
        return null;
    }

    public static boolean hasRoleScopeProfile(CanonicalSecurityContext context) {
        return context != null
                && context.getRoleScopeProfile() != null
                && (StringUtils.hasText(context.getRoleScopeProfile().getSummary())
                || StringUtils.hasText(context.getRoleScopeProfile().getCurrentResourceFamily())
                || StringUtils.hasText(context.getRoleScopeProfile().getCurrentActionFamily())
                || !context.getRoleScopeProfile().getExpectedResourceFamilies().isEmpty()
                || !context.getRoleScopeProfile().getExpectedActionFamilies().isEmpty()
                || !context.getRoleScopeProfile().getForbiddenResourceFamilies().isEmpty()
                || !context.getRoleScopeProfile().getForbiddenActionFamilies().isEmpty()
                || !context.getRoleScopeProfile().getRecentPermissionChanges().isEmpty()
                || context.getRoleScopeProfile().getResourceFamilyDrift() != null
                || context.getRoleScopeProfile().getActionFamilyDrift() != null
                || StringUtils.hasText(context.getRoleScopeProfile().getTemporaryElevationReason())
                || context.getRoleScopeProfile().getTemporaryElevation() != null);
    }

    public static boolean hasFrictionProfile(CanonicalSecurityContext context) {
        return context != null
                && context.getFrictionProfile() != null
                && (StringUtils.hasText(context.getFrictionProfile().getSummary())
                || context.getFrictionProfile().getRecentChallengeCount() != null
                || context.getFrictionProfile().getRecentBlockCount() != null
                || context.getFrictionProfile().getRecentEscalationCount() != null
                || context.getFrictionProfile().getApprovalRequired() != null
                || !context.getFrictionProfile().getApprovalLineage().isEmpty()
                || !context.getFrictionProfile().getPendingApproverRoles().isEmpty()
                || StringUtils.hasText(context.getFrictionProfile().getApprovalTicketId())
                || context.getFrictionProfile().getApprovalDecisionAgeMinutes() != null
                || context.getFrictionProfile().getRecentDeniedAccessCount() != null
                || context.getFrictionProfile().getBreakGlass() != null
                || context.getFrictionProfile().getBlockedUser() != null);
    }

    public static boolean hasDelegationContext(CanonicalSecurityContext context) {
        return context != null
                && context.getDelegation() != null
                && (Boolean.TRUE.equals(context.getDelegation().getDelegated())
                || StringUtils.hasText(context.getDelegation().getAgentId())
                || StringUtils.hasText(context.getDelegation().getObjectiveId())
                || StringUtils.hasText(context.getDelegation().getObjectiveFamily())
                || StringUtils.hasText(context.getDelegation().getObjectiveSummary())
                || !context.getDelegation().getAllowedOperations().isEmpty()
                || !context.getDelegation().getAllowedResources().isEmpty()
                || context.getDelegation().getApprovalRequired() != null
                || context.getDelegation().getPrivilegedExportAllowed() != null
                || context.getDelegation().getContainmentOnly() != null);
    }

    public static boolean hasObjectiveDriftAssessment(CanonicalSecurityContext context) {
        return hasDelegationContext(context)
                && context.getDelegation() != null
                && context.getDelegation().getObjectiveDrift() != null;
    }

    public static boolean hasPeerCohortProfile(CanonicalSecurityContext context) {
        return context != null
                && context.getPeerCohortProfile() != null
                && (StringUtils.hasText(context.getPeerCohortProfile().getCohortId())
                || StringUtils.hasText(context.getPeerCohortProfile().getSummary())
                || !context.getPeerCohortProfile().getPreferredResources().isEmpty()
                || !context.getPeerCohortProfile().getPreferredActionFamilies().isEmpty()
                || StringUtils.hasText(context.getPeerCohortProfile().getNormalProtectableFrequencyBand())
                || StringUtils.hasText(context.getPeerCohortProfile().getNormalSensitivityBand())
                || context.getPeerCohortProfile().getOutlierAgainstCohort() != null);
    }

    public static boolean hasReasoningMemoryProfile(CanonicalSecurityContext context) {
        return context != null
                && context.getReasoningMemoryProfile() != null
                && (StringUtils.hasText(context.getReasoningMemoryProfile().getSummary())
                || context.getReasoningMemoryProfile().getReinforcedCaseCount() != null
                || context.getReasoningMemoryProfile().getHardNegativeCaseCount() != null
                || context.getReasoningMemoryProfile().getFalseNegativeCaseCount() != null
                || context.getReasoningMemoryProfile().getKnowledgeAssistedCaseCount() != null
                || StringUtils.hasText(context.getReasoningMemoryProfile().getObjectiveAwareReasoningMemory())
                || StringUtils.hasText(context.getReasoningMemoryProfile().getRetentionTier())
                || StringUtils.hasText(context.getReasoningMemoryProfile().getRecallPriority())
                || StringUtils.hasText(context.getReasoningMemoryProfile().getFreshnessState())
                || StringUtils.hasText(context.getReasoningMemoryProfile().getReasoningState())
                || StringUtils.hasText(context.getReasoningMemoryProfile().getCohortPreference())
                || StringUtils.hasText(context.getReasoningMemoryProfile().getMemoryRiskProfile())
                || context.getReasoningMemoryProfile().getRetrievalWeight() != null
                || !context.getReasoningMemoryProfile().getMatchedSignalKeys().isEmpty()
                || !context.getReasoningMemoryProfile().getObjectiveFamilies().isEmpty()
                || !context.getReasoningMemoryProfile().getMemoryGuardrails().isEmpty()
                || !context.getReasoningMemoryProfile().getXaiLinkedFacts().isEmpty()
                || !context.getReasoningMemoryProfile().getReasoningFacts().isEmpty()
                || StringUtils.hasText(context.getReasoningMemoryProfile().getCrossTenantObjectiveMisusePackSummary())
                || !context.getReasoningMemoryProfile().getCrossTenantObjectiveMisuseFacts().isEmpty());
    }

    public static ContextCoverageLevel determineCoverageLevel(CanonicalSecurityContext context) {
        boolean identityAware = hasActorIdentity(context);
        boolean sessionAware = hasSessionIdentity(context);
        boolean scopeAware = hasEffectiveRoles(context) || hasAuthorizationScope(context);
        boolean businessAware = hasResourceBusinessSemantics(context)
                && (hasObservedScope(context)
                || hasSessionNarrativeProfile(context)
                || hasWorkProfile(context)
                || hasRoleScopeProfile(context)
                || hasPeerCohortProfile(context)
                || hasFrictionProfile(context)
                || hasReasoningMemoryProfile(context));

        if (identityAware && sessionAware && scopeAware && businessAware) {
            return ContextCoverageLevel.BUSINESS_AWARE;
        }
        if (identityAware && scopeAware) {
            return ContextCoverageLevel.SCOPE_AWARE;
        }
        if (identityAware) {
            return ContextCoverageLevel.IDENTITY_AWARE;
        }
        return ContextCoverageLevel.ENVIRONMENT_ONLY;
    }
}
