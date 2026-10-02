package io.contexa.demo.experience.factor.dto;

import io.contexa.demo.comparison.variation.dto.RunVariation;
import io.contexa.demo.experience.report.dto.StoredReport;

public record FactorPair(
        int repetition,
        StoredReport before,
        StoredReport after,
        RunVariation conditions
) {
}
