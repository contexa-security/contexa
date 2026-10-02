package io.contexa.demo.experience.journey.dto;

import io.contexa.demo.scenario.dto.ScenarioEvaluation;
import io.contexa.demo.scenario.dto.StoredScenario;
import java.util.List;

public record JourneySnapshot(
        String version,
        String account,
        StoredScenario scenario,
        ScenarioEvaluation evaluation,
        List<String> limitations
) {
}
