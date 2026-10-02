package io.contexa.demo.comparison.run.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.manifest.evaluation.dto.FrozenReviewContract;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.comparison.variation.dto.RunVariation;
import io.contexa.demo.experience.journey.dto.FrozenJourneyStep;
import io.contexa.demo.experience.history.dto.FrozenHistoryReference;
import java.util.List;
import java.util.UUID;

public record RunManifest(
        String version,
        UUID preparationId,
        String preparationSha256,
        ComparisonRequestPlan plan,
        List<ArmAttestation> initialConditions,
        RequestSchedule schedule,
        String evaluationContract,
        List<String> evidenceLimitations,
        @JsonInclude(JsonInclude.Include.NON_NULL) ReadinessReport executionReadiness,
        @JsonInclude(JsonInclude.Include.NON_NULL) FrozenReviewContract reviewContract,
        @JsonInclude(JsonInclude.Include.NON_NULL) RunVariation variation,
        @JsonInclude(JsonInclude.Include.NON_NULL) FrozenJourneyStep journeyStep,
        @JsonInclude(JsonInclude.Include.NON_NULL) FrozenHistoryReference historyReference
) {
}
