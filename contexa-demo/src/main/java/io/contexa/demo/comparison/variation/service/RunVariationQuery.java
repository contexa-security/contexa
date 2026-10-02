package io.contexa.demo.comparison.variation.service;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.comparison.variation.dto.RunVariation;
import java.util.List;
import java.util.UUID;

public interface RunVariationQuery {

    void requireParent(UUID visitorId, UUID parentRunId, String account);

    RunVariation capture(UUID visitorId, ComparisonRequestPlan plan, List<ArmAttestation> current);
}
