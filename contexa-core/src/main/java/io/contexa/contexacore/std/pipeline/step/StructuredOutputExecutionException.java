package io.contexa.contexacore.std.pipeline.step;

public class StructuredOutputExecutionException extends IllegalStateException {

    private final StructuredOutputFailureCategory category;
    private final DecisionExecutionFailure failure;

    public StructuredOutputExecutionException(StructuredOutputFailureCategory category, String message) {
        super(message);
        this.category = category;
        this.failure = new DecisionExecutionFailure(category.toDecisionFailureCategory(), message, null);
    }

    public StructuredOutputExecutionException(StructuredOutputFailureCategory category, String message, Throwable cause) {
        super(message, cause);
        this.category = category;
        this.failure = new DecisionExecutionFailure(category.toDecisionFailureCategory(), message, null);
    }

    public StructuredOutputExecutionException(StructuredOutputFailureCategory category, DecisionExecutionFailure failure) {
        super(failure != null ? failure.message() : null);
        this.category = category;
        this.failure = failure != null
                ? failure
                : new DecisionExecutionFailure(category.toDecisionFailureCategory(), "", null);
    }

    public StructuredOutputExecutionException(StructuredOutputFailureCategory category, DecisionExecutionFailure failure, Throwable cause) {
        super(failure != null ? failure.message() : null, cause);
        this.category = category;
        this.failure = failure != null
                ? failure
                : new DecisionExecutionFailure(category.toDecisionFailureCategory(), "", null);
    }

    public StructuredOutputFailureCategory getCategory() {
        return category;
    }

    public DecisionExecutionFailure getFailure() {
        return failure;
    }
}
