package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.adjudication.SealedEvidencePromptScorecard;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;

public class DefaultRuntimeEvidencePromptScorecardService implements RuntimeEvidencePromptScorecardService {

    private final SealedEvidencePromptScorecard promptScorecard;

    public DefaultRuntimeEvidencePromptScorecardService(SealedEvidencePromptScorecard promptScorecard) {
        this.promptScorecard = promptScorecard;
    }

    @Override
    public ScorecardResult evaluate(SealedEvidencePackage evidencePackage) {
        return promptScorecard.evaluate(evidencePackage);
    }
}

