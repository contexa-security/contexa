package io.contexa.contexacore.autonomous.context;

import org.springframework.util.StringUtils;

import java.util.*;

public class CanonicalSecurityContextHardener {

    public CanonicalSecurityContext harden(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }

        if (context.getActor() == null) {
            context.setActor(new CanonicalSecurityContext.Actor());
        }
        if (context.getSession() == null) {
            context.setSession(new CanonicalSecurityContext.Session());
        }
        if (context.getResource() == null) {
            context.setResource(new CanonicalSecurityContext.Resource());
        }
        if (context.getAuthorization() == null) {
            context.setAuthorization(new CanonicalSecurityContext.Authorization());
        }
        if (context.getDelegation() == null) {
            context.setDelegation(new CanonicalSecurityContext.Delegation());
        }

        hardenActor(context.getActor());
        hardenSession(context.getSession());
        hardenResource(context.getResource());
        hardenAuthorization(context.getAuthorization());
        hardenDelegation(context.getDelegation());
        if (context.getObservedScope() != null) {
            hardenObservedScope(context.getObservedScope());
        }
        if (context.getAttributes() == null) {
            context.setAttributes(Map.of());
        }
        return context;
    }

    private void hardenActor(CanonicalSecurityContext.Actor actor) {
        actor.setUserId(normalizeText(actor.getUserId()));
        actor.setOrganizationId(normalizeText(actor.getOrganizationId()));
        actor.setDepartment(normalizeText(actor.getDepartment()));
        actor.setPrincipalType(normalizeUpperText(actor.getPrincipalType()));
        actor.setRoleSet(normalizeList(actor.getRoleSet()));
        actor.setAuthoritySet(normalizeList(actor.getAuthoritySet()));
    }

    private void hardenSession(CanonicalSecurityContext.Session session) {
        session.setSessionId(normalizeText(session.getSessionId()));
        session.setClientIp(normalizeText(session.getClientIp()));
        session.setUserAgent(normalizeText(session.getUserAgent()));
        session.setFailedLoginAttempts(normalizeInteger(session.getFailedLoginAttempts()));
        session.setRecentRequestCount(normalizeInteger(session.getRecentRequestCount()));
    }

    private void hardenResource(CanonicalSecurityContext.Resource resource) {
        resource.setResourceId(normalizeText(resource.getResourceId()));
        resource.setResourceType(normalizeUpperText(resource.getResourceType()));
        resource.setBusinessLabel(normalizeText(resource.getBusinessLabel()));
        resource.setSensitivity(normalizeUpperText(resource.getSensitivity()));
        resource.setRequestPath(normalizeText(resource.getRequestPath()));
        resource.setHttpMethod(normalizeUpperText(resource.getHttpMethod()));
        resource.setActionFamily(normalizeUpperText(resource.getActionFamily()));
    }

    private void hardenAuthorization(CanonicalSecurityContext.Authorization authorization) {
        authorization.setEffectiveRoles(normalizeList(authorization.getEffectiveRoles()));
        authorization.setEffectivePermissions(normalizeList(authorization.getEffectivePermissions()));
        authorization.setScopeTags(normalizeList(authorization.getScopeTags()));
    }

    private void hardenDelegation(CanonicalSecurityContext.Delegation delegation) {
        delegation.setAgentId(normalizeText(delegation.getAgentId()));
        delegation.setObjectiveId(normalizeText(delegation.getObjectiveId()));
        delegation.setObjectiveFamily(normalizeUpperText(delegation.getObjectiveFamily()));
        delegation.setAllowedOperations(normalizeList(delegation.getAllowedOperations()));
        delegation.setAllowedResources(normalizeList(delegation.getAllowedResources()));
    }

    private void hardenObservedScope(CanonicalSecurityContext.ObservedScope observedScope) {
        observedScope.setProfileSource(normalizeUpperText(observedScope.getProfileSource()));
        observedScope.setSummary(normalizeText(observedScope.getSummary()));
        observedScope.setRecentProtectableAccessCount(normalizeInteger(observedScope.getRecentProtectableAccessCount()));
        observedScope.setRecentDeniedAccessCount(normalizeInteger(observedScope.getRecentDeniedAccessCount()));
        observedScope.setRecentSensitiveAccessCount(normalizeInteger(observedScope.getRecentSensitiveAccessCount()));
        observedScope.setFrequentResources(normalizeList(observedScope.getFrequentResources()));
        observedScope.setFrequentActionFamilies(normalizeList(observedScope.getFrequentActionFamilies()));
    }

    private Integer normalizeInteger(Integer value) {
        if (value == null) {
            return null;
        }
        return Math.max(value, 0);
    }

    private String normalizeText(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return value.trim();
    }

    private String normalizeUpperText(String value) {
        String normalized = normalizeText(value);
        if (normalized == null) {
            return null;
        }
        return normalized.toUpperCase(Locale.ROOT);
    }

    private List<String> normalizeList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        for (String value : values) {
            String normalizedValue = normalizeText(value);
            if (normalizedValue != null) {
                normalized.add(normalizedValue);
            }
        }
        return new ArrayList<>(normalized);
    }
}
