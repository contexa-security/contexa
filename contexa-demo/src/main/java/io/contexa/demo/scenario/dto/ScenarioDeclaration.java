package io.contexa.demo.scenario.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record ScenarioDeclaration(
        @Pattern(regexp = "S[0-9]{2}") String key,
        @Min(1) int version,
        @NotNull @Valid ScenarioDefinition definition,
        @NotNull @Valid ScenarioOracle oracle
) {

}
