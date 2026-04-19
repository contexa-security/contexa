package io.contexa.contexacore.std.pipeline.step;

public enum StructuredOutputFailureCategory {
    ENTITY_EXECUTION_FAILED,
    STRUCTURED_OUTPUT_MISSING,
    EMPTY_RESPONSE,
    RAW_EXECUTION_FORBIDDEN,
    VALIDATION_FAILED;

    public DecisionFailureCategory toDecisionFailureCategory() {
        return DecisionFailureCategory.fromStructuredOutput(this);
    }
}
