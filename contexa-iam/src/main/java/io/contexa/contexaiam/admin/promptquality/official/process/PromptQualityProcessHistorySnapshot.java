package io.contexa.contexaiam.admin.promptquality.official.process;

import java.time.Instant;

public record PromptQualityProcessHistorySnapshot(
        String processCode,
        String stepCode,
        String fromState,
        String toState,
        String fromDomainStateDimension,
        String fromDomainStateCode,
        String toDomainStateDimension,
        String toDomainStateCode,
        String evidenceRef,
        String changedBy,
        String reason,
        Instant changedAt) {
}
