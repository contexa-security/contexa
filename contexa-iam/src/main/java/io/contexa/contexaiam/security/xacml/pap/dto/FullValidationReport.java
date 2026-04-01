package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

public record FullValidationReport(
        long totalPolicies,
        String healthStatus,
        List<PolicyConflictDto> conflicts,
        List<DuplicatePolicyDto> duplicates) {

    public static String computeHealthStatus(List<PolicyConflictDto> conflicts) {
        if (conflicts.stream().anyMatch(c -> c.severity() == PolicyConflictDto.Severity.CRITICAL)) {
            return "CRITICAL";
        }
        if (!conflicts.isEmpty()) {
            return "WARNING";
        }
        return "HEALTHY";
    }
}
