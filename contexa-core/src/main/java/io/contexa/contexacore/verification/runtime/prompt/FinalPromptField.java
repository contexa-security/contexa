package io.contexa.contexacore.verification.runtime.prompt;

public record FinalPromptField(
        String section,
        String label,
        String value,
        int lineNumber,
        String semanticKey,
        String promptLocation,
        boolean mappedToContract,
        String parentGroup,
        String securityRelevance,
        String attackSignalRole
) {
    public FinalPromptField(
            String section,
            String label,
            String value,
            int lineNumber,
            String semanticKey,
            String promptLocation,
            boolean mappedToContract) {
        this(
                section,
                label,
                value,
                lineNumber,
                semanticKey,
                promptLocation,
                mappedToContract,
                "",
                FinalPromptSemanticModel.securityRelevance(section, label),
                FinalPromptSemanticModel.attackSignalRole(section, label, value));
    }

    public FinalPromptField(String section, String label, String value, int lineNumber) {
        this(
                section,
                label,
                value,
                lineNumber,
                FinalPromptSemanticModel.semanticKey(section, label),
                FinalPromptSemanticModel.semanticKey(section, label),
                true,
                "",
                FinalPromptSemanticModel.securityRelevance(section, label),
                FinalPromptSemanticModel.attackSignalRole(section, label, value));
    }
}
