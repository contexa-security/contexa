package io.contexa.contexacore.verification.runtime.prompt;

public record FinalPromptBullet(
        String section,
        String text,
        int lineNumber,
        String parentGroup,
        String semanticKey,
        String promptLocation,
        String attackSignalRole
) {
    public FinalPromptBullet(String section, String text, int lineNumber) {
        this(
                section,
                text,
                lineNumber,
                "",
                FinalPromptSemanticModel.semanticKey(section, text),
                FinalPromptSemanticModel.semanticKey(section, text),
                FinalPromptSemanticModel.attackSignalRole(section, text, text));
    }
}
