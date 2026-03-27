package io.contexa.contexacore.autonomous.context;

/**
 * Evidence sufficiency only. This grade is audit/runtime metadata and must never be treated as a
 * semantic verdict about legitimacy, abuse, or user intent.
 */
public enum ContextQualityGrade {
    STRONG,
    MODERATE,
    WEAK,
    REJECTED;

    public boolean permitsStandaloneEvidenceUse() {
        return this == STRONG || this == MODERATE;
    }

    /**
     * @deprecated Use {@link #permitsStandaloneEvidenceUse()} to avoid implying that system-side
     * evidence grades replace LLM semantic reasoning.
     */
    @Deprecated(since = "0.1.0", forRemoval = false)
    public boolean supportsReasoning() {
        return permitsStandaloneEvidenceUse();
    }
}
