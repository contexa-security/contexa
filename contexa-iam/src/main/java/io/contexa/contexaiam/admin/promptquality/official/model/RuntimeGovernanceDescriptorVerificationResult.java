package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record RuntimeGovernanceDescriptorVerificationResult(
        boolean passed,
        List<RuntimeEvidenceCheckResult> checks,
        List<String> findings,
        List<String> nextActions
) {

    public static RuntimeGovernanceDescriptorVerificationResult empty() {
        return new RuntimeGovernanceDescriptorVerificationResult(true, List.of(), List.of(), List.of());
    }
}
