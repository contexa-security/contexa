package io.contexa.contexacore.verification.contract.prompt;

/**
 * Session boundary mode for one official verification round.
 *
 * Long-horizon benchmarks must distinguish:
 * - same-session follow-up actions
 * - same-account but new-session re-entry on a later day/time
 */
public enum OfficialVerificationPromptContractSessionMode {
    REUSE_SESSION,
    NEW_SESSION
}