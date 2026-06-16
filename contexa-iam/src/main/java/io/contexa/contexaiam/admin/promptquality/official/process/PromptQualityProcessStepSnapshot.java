package io.contexa.contexaiam.admin.promptquality.official.process;

import java.time.Instant;

public record PromptQualityProcessStepSnapshot(
        String stepCode,
        int sequenceNo,
        String executionState,
        String domainStateDimension,
        String domainStateCode,
        String evidenceRef,
        String route,
        String summary,
        String nextAction,
        Instant startedAt,
        Instant endedAt) {
}

