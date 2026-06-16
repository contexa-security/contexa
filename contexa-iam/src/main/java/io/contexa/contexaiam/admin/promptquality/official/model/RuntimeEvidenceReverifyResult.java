package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record RuntimeEvidenceReverifyResult(
        String packageId,
        RuntimeEvidenceVerificationRun run,
        String nextRequestInstruction,
        String sourcePackageId,
        String sourceAggregateRunId,
        boolean linkedCriteriaSatisfied,
        List<RuntimeEvidenceReverifyFindingResult> findingResults) {

    public RuntimeEvidenceReverifyResult(
            String packageId,
            RuntimeEvidenceVerificationRun run,
            String nextRequestInstruction) {
        this(packageId, run, nextRequestInstruction, null, null, false, List.of());
    }

    public RuntimeEvidenceReverifyResult {
        findingResults = findingResults == null ? List.of() : List.copyOf(findingResults);
    }
}

