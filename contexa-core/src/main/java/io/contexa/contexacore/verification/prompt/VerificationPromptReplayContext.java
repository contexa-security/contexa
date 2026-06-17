package io.contexa.contexacore.verification.prompt;

/**
 * Normalized prompt context used by replay and experiment services.
 */
public record VerificationPromptReplayContext(
        String systemPrompt,
        String userPrompt,
        String rawSystemPrompt,
        String rawUserPrompt,
        String promptHash,
        VerificationPromptFidelityReport fidelityReport
) {
}
