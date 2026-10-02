package io.contexa.demo.scenario.dto;

import io.contexa.demo.scenario.domain.Operation;
import io.contexa.demo.scenario.domain.Selector;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record ScenarioStep(
        @NotBlank String stepId,
        @NotNull Operation operation,
        @NotNull Selector selector,
        @Min(1) int maxItems
) {

}
