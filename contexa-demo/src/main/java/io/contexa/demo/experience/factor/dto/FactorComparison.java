package io.contexa.demo.experience.factor.dto;

import java.time.Instant;
import java.util.List;

public record FactorComparison(
        String version,
        ComparisonFactor intendedFactor,
        Instant assembledAt,
        List<FactorPair> repetitions,
        String reviewState,
        List<String> limitations
) {
}
