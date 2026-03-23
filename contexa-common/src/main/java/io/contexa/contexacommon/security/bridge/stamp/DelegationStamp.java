package io.contexa.contexacommon.security.bridge.stamp;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public record DelegationStamp(
        String subjectId,
        String agentId,
        boolean delegated,
        String objectiveId,
        String objectiveSummary,
        List<String> allowedOperations,
        List<String> allowedResources,
        Boolean approvalRequired,
        Boolean containmentOnly,
        Instant expiresAt,
        Map<String, Object> attributes
) {

    public DelegationStamp {
        allowedOperations = allowedOperations == null ? List.of() : List.copyOf(new LinkedHashSet<>(allowedOperations));
        allowedResources = allowedResources == null ? List.of() : List.copyOf(new LinkedHashSet<>(allowedResources));
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }
}
