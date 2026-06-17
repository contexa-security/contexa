package io.contexa.contexacore.verification.prompt;

import java.util.List;

/**
 * Prompt fidelity assessment attached to replay and experiment prompt contexts.
 */
public record VerificationPromptFidelityReport(
        VerificationPromptFidelityLevel level,
        boolean rawPromptPresent,
        boolean llmViewPromptPresent,
        boolean promptHashPresent,
        boolean rebuiltFromCanonicalContext,
        boolean fullPromptRebuilt,
        List<String> findings
) {

    public VerificationPromptFidelityReport {
        findings = findings == null ? List.of() : List.copyOf(findings);
    }
}
