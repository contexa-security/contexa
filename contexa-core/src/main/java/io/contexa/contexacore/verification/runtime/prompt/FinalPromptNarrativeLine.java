package io.contexa.contexacore.verification.runtime.prompt;

public record FinalPromptNarrativeLine(
        String section,
        String text,
        int lineNumber,
        String semanticKey,
        String promptLocation,
        String attackSignalRole
) {
    public FinalPromptNarrativeLine(String section, String text, int lineNumber) {
        this(
                section,
                text,
                lineNumber,
                FinalPromptSemanticModel.semanticKey(section, text),
                FinalPromptSemanticModel.semanticKey(section, text),
                FinalPromptSemanticModel.attackSignalRole(section, text, text));
    }
}
