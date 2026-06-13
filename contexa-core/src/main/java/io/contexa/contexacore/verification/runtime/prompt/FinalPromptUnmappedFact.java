package io.contexa.contexacore.verification.runtime.prompt;

public record FinalPromptUnmappedFact(
        String section,
        String label,
        String value,
        int lineNumber,
        String sourceLine,
        String errorCode
) {
    public FinalPromptUnmappedFact(
            String section,
            String label,
            String value,
            int lineNumber,
            String sourceLine) {
        this(section, label, value, lineNumber, sourceLine, "UNMAPPED_PROMPT_FACT");
    }
}
