package io.contexa.contexacore.verification.prompt;

/**
 * Fidelity level of a replayable prompt reconstructed from sealed evidence.
 */
public enum VerificationPromptFidelityLevel {
    FULL_REBUILT,
    PARTIAL_REBUILT,
    EVIDENCE_ONLY,
    UNVERIFIABLE
}
