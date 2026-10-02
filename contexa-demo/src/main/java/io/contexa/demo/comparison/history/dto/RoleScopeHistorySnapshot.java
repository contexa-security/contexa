package io.contexa.demo.comparison.history.dto;

import java.time.Instant;

public record RoleScopeHistorySnapshot(
        String state,
        Instant readStartedAt,
        Instant readFinishedAt,
        String authorizationStateSha256,
        String scopeKeySha256,
        Integer observedEntries,
        Integer readLimit,
        String observationsSha256,
        String consistencyBoundary
) {
}
