package io.contexa.contexacore.std.components.prompt;

import java.util.Objects;

public record PromptViewComposition(
        String rawSystemPrompt,
        String rawUserPrompt,
        String llmSystemPrompt,
        String llmUserPrompt,
        PromptCompressionLedger compressionLedger) {

    public PromptViewComposition {
        rawSystemPrompt = normalize(rawSystemPrompt);
        rawUserPrompt = normalize(rawUserPrompt);
        llmSystemPrompt = normalize(llmSystemPrompt);
        llmUserPrompt = normalize(llmUserPrompt);
        compressionLedger = Objects.requireNonNull(compressionLedger, "compressionLedger");
    }

    private static String normalize(String value) {
        return value != null ? value : "";
    }
}