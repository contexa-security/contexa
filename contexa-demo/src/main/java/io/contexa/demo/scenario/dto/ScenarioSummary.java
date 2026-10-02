package io.contexa.demo.scenario.dto;

import java.time.Instant;
import java.util.UUID;

public record ScenarioSummary(
        UUID id,
        String key,
        int version,
        ScenarioDisplay display,
        String contentSha256,
        Instant createdAt
) {

}
