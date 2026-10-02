package io.contexa.demo.experience.history.service;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.experience.history.dto.FrozenHistoryReference;
import java.util.List;
import java.util.UUID;

public interface HistoryReferenceQuery {

    FrozenHistoryReference capture(UUID visitorId, ComparisonRequestPlan plan, List<ArmAttestation> current);
}
