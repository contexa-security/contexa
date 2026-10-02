package io.contexa.demo.scenario.dto;

import java.time.Instant;
import java.util.UUID;

public record StoredScenario(
        UUID id,
        String key,
        int version,
        ScenarioDefinition definition,
        String contentSha256,
        Instant createdAt
) {

}
