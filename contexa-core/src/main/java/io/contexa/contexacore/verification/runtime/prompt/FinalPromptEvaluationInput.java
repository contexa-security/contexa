package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;

import java.util.Objects;

public record FinalPromptEvaluationInput(
        SealedEvidencePackage evidencePackage,
        FinalPromptSnapshot prompt,
        FinalPromptSemanticModel semanticModel,
        FinalPromptEvidenceContext evidence
) {

    public static FinalPromptEvaluationInput from(
            SealedEvidencePackage evidencePackage,
            FinalPromptParser parser,
            FinalPromptPreflightResult preflight,
            ObjectMapper objectMapper) {
        FinalPromptParser effectiveParser = Objects.requireNonNull(parser, "parser");
        Objects.requireNonNull(objectMapper, "objectMapper");
        FinalPromptSnapshot prompt = effectiveParser.parse(evidencePackage == null ? null : evidencePackage.getUserPromptText());
        return new FinalPromptEvaluationInput(
                evidencePackage,
                prompt,
                FinalPromptSemanticModel.from(prompt),
                FinalPromptEvidenceContext.from(evidencePackage, preflight, objectMapper));
    }
}
