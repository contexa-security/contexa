package io.contexa.contexacore.std.security;

import java.util.List;

public record PromptSafetyDecision(
        boolean allowed,
        String decision,
        List<String> flags) {

    public PromptSafetyDecision {
        flags = flags == null ? List.of() : List.copyOf(flags);
    }

    public static PromptSafetyDecision allow() {
        return new PromptSafetyDecision(true, "ALLOWED_PROMPT_SAFE", List.of());
    }

    public static PromptSafetyDecision deny(List<String> flags) {
        return new PromptSafetyDecision(false, "DENIED_PROMPT_SAFETY", flags);
    }
}