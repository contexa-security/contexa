package io.contexa.demo.scenario.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record ScenarioDefinition(
        @NotNull @Valid ScenarioDisplay display,
        @NotNull @Valid ScenarioInitialState initialState,
        @NotEmpty List<@Valid ScenarioStep> requestPlan,
        @NotNull @Valid ScenarioConditions conditions,
        @NotEmpty List<String> mutableConditions,
        @NotBlank String timeSource
) {

}
