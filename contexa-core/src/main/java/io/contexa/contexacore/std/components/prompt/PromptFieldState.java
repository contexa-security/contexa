package io.contexa.contexacore.std.components.prompt;

public enum PromptFieldState {
    VALUE_PRESENT(false),
    NULL_ALLOWED(false),
    UNKNOWN_WITH_REASON(false),
    NOT_APPLICABLE(false),
    PRODUCER_NOT_AVAILABLE(false),
    OMITTED_BY_POLICY(false),
    COMPACTED_WITH_FULL_SOURCE(false),
    REQUIRED_MISSING(true),
    CONDITIONAL_REQUIRED_MISSING(true),
    UNKNOWN_WITHOUT_REASON(true),
    CONTRACT_MISMATCH(true);

    private final boolean blockingCandidate;

    PromptFieldState(boolean blockingCandidate) {
        this.blockingCandidate = blockingCandidate;
    }

    public boolean blockingCandidate() {
        return blockingCandidate;
    }
}
