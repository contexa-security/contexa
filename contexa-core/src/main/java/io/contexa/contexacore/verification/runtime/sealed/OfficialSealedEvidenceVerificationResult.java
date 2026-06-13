package io.contexa.contexacore.verification.runtime.sealed;

import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;

import java.util.List;

public record OfficialSealedEvidenceVerificationResult(
        String aggregateRunId,
        String packageId,
        String operatorId,
        String generatedAt,
        boolean integrityValid,
        List<OfficialVerificationRunView> runs
) {
}
