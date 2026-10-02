package io.contexa.demo.scenario.dto;

import java.util.UUID;

public record ScenarioEvaluation(
        UUID scenarioId,
        ScenarioOracle oracle,
        String contentSha256
) {

}
