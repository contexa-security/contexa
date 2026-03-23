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

    public static ContextCoverageLevel determineCoverageLevel(CanonicalSecurityContext context) {
        boolean identityAware = hasActorIdentity(context);
        boolean sessionAware = hasSessionIdentity(context);
        boolean scopeAware = hasEffectiveRoles(context) || hasAuthorizationScope(context);
        boolean businessAware = hasResourceBusinessSemantics(context);

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
