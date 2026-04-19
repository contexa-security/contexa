package io.contexa.contexacore.std.pipeline.step;

public enum DecisionFailureCategory {
    ENTITY_EXECUTION_FAILED,
    STRUCTURED_OUTPUT_MISSING,
    EMPTY_RESPONSE,
    RAW_EXECUTION_FORBIDDEN,
    VALIDATION_FAILED;

    public static DecisionFailureCategory fromStructuredOutput(StructuredOutputFailureCategory category) {
        if (category == null) {
            return ENTITY_EXECUTION_FAILED;
        }
        return switch (category) {
            case ENTITY_EXECUTION_FAILED -> ENTITY_EXECUTION_FAILED;
            case STRUCTURED_OUTPUT_MISSING -> STRUCTURED_OUTPUT_MISSING;
            case EMPTY_RESPONSE -> EMPTY_RESPONSE;
            case RAW_EXECUTION_FORBIDDEN -> RAW_EXECUTION_FORBIDDEN;
            case VALIDATION_FAILED -> VALIDATION_FAILED;
        };
    }
}
