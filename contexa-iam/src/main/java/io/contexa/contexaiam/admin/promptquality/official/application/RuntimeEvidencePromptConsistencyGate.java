package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;

public interface RuntimeEvidencePromptConsistencyGate {

    RuntimeEvidencePromptConsistencyResult evaluate(SealedEvidencePackage evidencePackage);
}
