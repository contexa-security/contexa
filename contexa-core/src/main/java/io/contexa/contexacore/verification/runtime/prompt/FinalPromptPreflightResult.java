package io.contexa.contexacore.verification.runtime.prompt;

import java.util.List;

public record FinalPromptPreflightResult(
        boolean ready,
        String userPromptHash,
        List<String> violations
) {

    public FinalPromptPreflightResult {
        violations = violations == null ? List.of() : List.copyOf(violations);
    }
}
