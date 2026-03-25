package io.contexa.contexacore.autonomous.context;

public enum ContextQualityGrade {
    STRONG,
    MODERATE,
    WEAK,
    REJECTED;

    public boolean supportsReasoning() {
        return this == STRONG || this == MODERATE;
    }
}
