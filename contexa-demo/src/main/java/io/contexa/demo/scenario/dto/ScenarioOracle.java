package io.contexa.demo.scenario.dto;

import io.contexa.demo.scenario.domain.Classification;
import io.contexa.demo.scenario.domain.ModelProposal;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record ScenarioOracle(
        @NotNull Classification classification,
        @NotEmpty List<ModelProposal> allowedModelProposals,
        @NotEmpty List<ModelProposal> allowedFinalResponses,
        @NotEmpty List<String> requiredEvidence,
        @NotBlank String rationale,
        boolean technicalFallbackCountsAsDetection,
        boolean staticDenialCountsAsDetection
) {

}
