package io.contexa.demo.experience.factor.service;

import io.contexa.demo.experience.factor.dto.ComparisonFactor;
import io.contexa.demo.experience.factor.dto.FactorComparison;
import java.util.List;
import java.util.UUID;

public interface FactorComparisonQuery {

    FactorComparison compare(UUID visitorId, ComparisonFactor factor, List<UUID> before, List<UUID> after);
}
