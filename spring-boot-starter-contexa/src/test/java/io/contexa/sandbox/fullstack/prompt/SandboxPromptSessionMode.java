package io.contexa.sandbox.fullstack.prompt;

/**
 * Session boundary mode for one benchmark round.
 *
 * Long-horizon behavioral benchmarks must distinguish:
 * - same-session follow-up actions
 * - same-account but new-session re-entry on a later day/time
 */
public enum SandboxPromptSessionMode {
    REUSE_SESSION,
    NEW_SESSION
}
