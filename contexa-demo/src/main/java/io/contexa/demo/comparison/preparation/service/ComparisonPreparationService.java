package io.contexa.demo.comparison.preparation.service;

import io.contexa.demo.comparison.preparation.dto.PreparationCommand;
import io.contexa.demo.comparison.preparation.dto.PreparedComparison;

import java.util.UUID;

public interface ComparisonPreparationService {

    PreparedComparison prepare(UUID visitorId, PreparationCommand command);

    PreparedComparison find(UUID visitorId, UUID id);
}
