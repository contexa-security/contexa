package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceGateResult;

import java.util.List;

public interface PromptQualityRuntimeCertificationPolicy {

    RuntimeEvidenceGateResult evaluate(
            SealedEvidencePackage evidencePackage,
            boolean integrityValid,
            ScorecardResult scorecard,
            DeterministicReplayResult replay,
            List<? extends OfficialVerificationRunView> metrics);
}
