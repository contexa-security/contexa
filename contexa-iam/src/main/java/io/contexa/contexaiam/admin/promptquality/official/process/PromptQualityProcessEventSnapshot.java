package io.contexa.contexaiam.admin.promptquality.official.process;

import java.time.Instant;

public record PromptQualityProcessEventSnapshot(
        String stepCode,
        String type,
        String payloadJson,
        Instant occurredAt) {
}
