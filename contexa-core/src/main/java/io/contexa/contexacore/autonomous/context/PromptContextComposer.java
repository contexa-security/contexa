package io.contexa.contexacore.autonomous.context;

import org.springframework.util.StringUtils;

import java.util.List;

public class PromptContextComposer {

    public String compose(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        appendBridgeSection(section, context.getBridge());
        appendCoverageSection(section, context.getCoverage());
        appendIdentitySection(section, context);
        appendResourceSection(section, context);
        appendObservedScopeSection(section, context.getObservedScope());
        appendDelegationSection(section, context);

        return section.isEmpty() ? null : section.toString();
    }

    private void appendBridgeSection(StringBuilder section, CanonicalSecurityContext.Bridge bridge) {
        if (bridge == null) {
            return;
        }
        section.append("\n=== BRIDGE RESOLUTION CONTEXT ===\n");
        appendLine(section, "BridgeCoverageLevel", bridge.getCoverageLevel());
        appendLine(section, "BridgeCoverageScore", bridge.getCoverageScore());
        appendLine(section, "BridgeCoverageSummary", bridge.getSummary());
        appendLine(section, "BridgeAuthenticationSource", bridge.getAuthenticationSource());
        appendLine(section, "BridgeAuthorizationSource", bridge.getAuthorizationSource());
        appendLine(section, "BridgeDelegationSource", bridge.getDelegationSource());
        appendList(section, "BridgeMissingContexts", bridge.getMissingContexts());
        appendList(section, "BridgeRemediationHints", bridge.getRemediationHints());
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
    }

    private void appendIdentitySection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.Actor actor = context.getActor();
        CanonicalSecurityContext.Authorization authorization = context.getAuthorization();
        CanonicalSecurityContext.Session session = context.getSession();
        if (actor == null && authorization == null && session == null) {
            return;
        }

        section.append("\n=== IDENTITY AND ROLE CONTEXT ===\n");
        if (actor != null) {
            appendLine(section, "UserId", actor.getUserId());
            appendLine(section, "OrganizationId", actor.getOrganizationId());
            appendLine(section, "Department", actor.getDepartment());
            appendLine(section, "PrincipalType", actor.getPrincipalType());
            appendList(section, "RoleSet", actor.getRoleSet());
            appendList(section, "AuthoritySet", actor.getAuthoritySet());
        }
        if (authorization != null) {
            appendList(section, "EffectiveRoles", authorization.getEffectiveRoles());
            appendList(section, "EffectivePermissions", authorization.getEffectivePermissions());
            appendList(section, "ScopeTags", authorization.getScopeTags());
            appendLine(section, "PrivilegedFlow", authorization.getPrivileged());
        }
        if (session != null) {
            appendLine(section, "SessionId", session.getSessionId());
            appendLine(section, "MfaVerified", session.getMfaVerified());
            appendLine(section, "FailedLoginAttempts", session.getFailedLoginAttempts());
            appendLine(section, "RecentRequestCount", session.getRecentRequestCount());
            appendLine(section, "NewSession", session.getNewSession());
            appendLine(section, "NewUser", session.getNewUser());
            appendLine(section, "NewDevice", session.getNewDevice());
        }
    }

    private void appendResourceSection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.Resource resource = context.getResource();
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

    private void appendDelegationSection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        if (delegation == null || !hasDelegationData(delegation)) {
            return;
        }

        section.append("\n=== DELEGATED OBJECTIVE CONTEXT ===\n");
        appendLine(section, "AgentId", delegation.getAgentId());
        appendLine(section, "ObjectiveId", delegation.getObjectiveId());
        appendLine(section, "ObjectiveFamily", delegation.getObjectiveFamily());
        appendList(section, "AllowedOperations", delegation.getAllowedOperations());
        appendList(section, "AllowedResources", delegation.getAllowedResources());
        appendLine(section, "PrivilegedExportAllowed", delegation.getPrivilegedExportAllowed());
        appendLine(section, "ContainmentOnly", delegation.getContainmentOnly());
    }

    private void appendObservedScopeSection(StringBuilder section, CanonicalSecurityContext.ObservedScope observedScope) {
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
        appendLine(section, "RareCurrentResource", observedScope.getRareCurrentResource());
        appendLine(section, "RareCurrentActionFamily", observedScope.getRareCurrentActionFamily());
    }

    private boolean hasDelegationData(CanonicalSecurityContext.Delegation delegation) {
        return StringUtils.hasText(delegation.getAgentId())
                || StringUtils.hasText(delegation.getObjectiveId())
                || StringUtils.hasText(delegation.getObjectiveFamily())
                || !delegation.getAllowedOperations().isEmpty()
                || !delegation.getAllowedResources().isEmpty()
                || delegation.getPrivilegedExportAllowed() != null
                || delegation.getContainmentOnly() != null;
    }

    private void appendList(StringBuilder section, String label, List<String> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        section.append(label)
                .append(": ")
                .append(String.join(", ", values))
                .append("\n");
    }

    private void appendLine(StringBuilder section, String label, Object value) {
        if (value == null) {
            return;
        }
        String text = value.toString();
        if (!StringUtils.hasText(text)) {
            return;
        }
        section.append(label)
                .append(": ")
                .append(text)
                .append("\n");
    }
}

