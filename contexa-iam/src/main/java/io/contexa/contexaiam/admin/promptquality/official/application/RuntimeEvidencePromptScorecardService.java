package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;

public interface RuntimeEvidencePromptScorecardService {

    ScorecardResult evaluate(SealedEvidencePackage evidencePackage);
}
