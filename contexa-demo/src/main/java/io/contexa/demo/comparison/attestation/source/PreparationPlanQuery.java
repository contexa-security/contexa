package io.contexa.demo.comparison.attestation.source;

import io.contexa.demo.comparison.preparation.dto.PreparedComparison;
import java.util.UUID;

public interface PreparationPlanQuery {

    PreparedComparison find(UUID visitorId, UUID preparationId);
}
