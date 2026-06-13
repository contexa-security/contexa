package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;

public record FinalPromptEvaluationInput(
        SealedEvidencePackage evidencePackage,
        FinalPromptSnapshot prompt,
        FinalPromptSemanticModel semanticModel,
        FinalPromptEvidenceContext evidence
) {

    public static FinalPromptEvaluationInput from(
            SealedEvidencePackage evidencePackage,
            FinalPromptParser parser) {
        return from(evidencePackage, parser, null, null);
    }

    public static FinalPromptEvaluationInput from(
            SealedEvidencePackage evidencePackage,
            FinalPromptParser parser,
            FinalPromptPreflightResult preflight,
            ObjectMapper objectMapper) {
        FinalPromptParser effectiveParser = parser == null ? new FinalPromptParser() : parser;
        FinalPromptSnapshot prompt = effectiveParser.parse(evidencePackage == null ? null : evidencePackage.getUserPromptText());
        return new FinalPromptEvaluationInput(
                evidencePackage,
                prompt,
                FinalPromptSemanticModel.from(prompt),
                FinalPromptEvidenceContext.from(evidencePackage, preflight, objectMapper));
    }
}
