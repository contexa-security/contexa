package io.contexa.contexacore.std.pipeline.step;

@Deprecated(forRemoval = false)
public class SecurityDecisionExecutionException extends IllegalStateException {

    private final DecisionFailureCategory category;
    private final DecisionExecutionFailure failure;

    public SecurityDecisionExecutionException(DecisionFailureCategory category, String message) {
        super(message);
        this.category = category;
        this.failure = new DecisionExecutionFailure(category, message, null);
    }

    public SecurityDecisionExecutionException(DecisionFailureCategory category, String message, Throwable cause) {
        super(message, cause);
        this.category = category;
        this.failure = new DecisionExecutionFailure(category, message, null);
    }

    public DecisionFailureCategory getCategory() {
        return category;
    }

    public DecisionExecutionFailure getFailure() {
        return failure;
    }
}
