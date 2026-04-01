package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

public record PolicyValidationReport(
        List<PolicyConflictDto> conflicts,
        List<DuplicatePolicyDto> duplicates,
        boolean canCreate,
        String blockedReason) {

    public boolean hasWarnings() {
        return !conflicts.isEmpty() || !duplicates.isEmpty();
    }
}
