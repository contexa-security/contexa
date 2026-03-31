package io.contexa.sandbox.fullstack.prompt;

import java.util.Locale;

public record SandboxDecisionConfidenceBand(double minInclusive, double maxInclusive) {

    public SandboxDecisionConfidenceBand {
        if (Double.isNaN(minInclusive) || Double.isNaN(maxInclusive)) {
            throw new IllegalArgumentException("confidence band must not contain NaN");
        }
        if (minInclusive < 0.0d || maxInclusive > 1.0d || minInclusive > maxInclusive) {
            throw new IllegalArgumentException("confidence band must be within [0,1] and ordered");
        }
    }

    public boolean contains(Double confidence) {
        if (confidence == null || confidence.isNaN() || confidence.isInfinite()) {
            return false;
        }
        return confidence >= minInclusive && confidence <= maxInclusive;
    }

    public String pretty() {
        return String.format(Locale.ROOT, "[%.2f, %.2f]", minInclusive, maxInclusive);
    }
}
