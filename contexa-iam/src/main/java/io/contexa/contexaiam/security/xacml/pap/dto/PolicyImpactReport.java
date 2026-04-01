package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

public record PolicyImpactReport(
        int affectedUserCount,
        List<AffectedUser> affectedUsers,
        List<AffectedResource> affectedResources,
        AccessChangeSummary accessChangeSummary) {

    public record AffectedUser(
            Long userId,
            String username,
            List<String> roles,
            List<String> groups,
            String currentAccess,
            String newAccess,
            String changeType) {
    }

    public record AffectedResource(
            String identifier,
            String httpMethod,
            int currentPolicyCount,
            List<String> matchedPolicyNames) {
    }

    public record AccessChangeSummary(
            int gained,
            int lost,
            int unchanged) {
    }
}
