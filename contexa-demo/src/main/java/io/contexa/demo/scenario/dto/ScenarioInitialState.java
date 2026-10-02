package io.contexa.demo.scenario.dto;

import jakarta.validation.constraints.NotBlank;

public record ScenarioInitialState(
        @NotBlank String history,
        @NotBlank String staticAuthorization,
        @NotBlank String identity,
        @NotBlank String businessDatasetContract
) {

}
