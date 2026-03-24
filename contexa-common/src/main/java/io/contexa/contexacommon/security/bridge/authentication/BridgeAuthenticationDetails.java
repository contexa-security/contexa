package io.contexa.contexacommon.security.bridge.authentication;

import java.io.Serializable;
import java.util.LinkedHashSet;
import java.util.List;

public record BridgeAuthenticationDetails(
        String bridgeAuthenticationSource,
        String bridgeAuthorizationSource,
        String bridgeDelegationSource,
        String bridgeCoverageLevel,
        Integer bridgeCoverageScore,
        List<String> bridgeMissingContexts,
        String bridgeCoverageSummary,
        List<String> bridgeRemediationHints,
        String authenticationType,
        String authenticationAssurance,
        Boolean mfaVerified,
        String organizationId,
        String orgId,
        String department,
        String authorizationEffect,
        Boolean privileged,
        String policyId,
        String policyVersion,
        List<String> scopeTags,
        List<String> effectiveRoles,
        List<String> effectiveAuthorities,
        Boolean delegated,
        String agentId,
        String objectiveId,
        String objectiveSummary,
        List<String> allowedOperations,
        List<String> allowedResources,
        Boolean approvalRequired,
        Boolean containmentOnly,
        Long internalUserId,
        String internalUsername,
        String bridgeSubjectKey,
        String externalSubjectId,
        Boolean bridgeManaged,
        Boolean externalAuthOnly
) implements Serializable {

    public BridgeAuthenticationDetails {
        bridgeMissingContexts = immutableList(bridgeMissingContexts);
        bridgeRemediationHints = immutableList(bridgeRemediationHints);
        scopeTags = immutableList(scopeTags);
        effectiveRoles = immutableList(effectiveRoles);
        effectiveAuthorities = immutableList(effectiveAuthorities);
        allowedOperations = immutableList(allowedOperations);
        allowedResources = immutableList(allowedResources);
    }

    private static List<String> immutableList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return List.copyOf(new LinkedHashSet<>(values));
    }
}
