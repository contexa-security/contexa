package io.contexa.demo.comparison.history.dto;

public record SessionClockSnapshot(
        String state,
        String source,
        Long startedAtEpochMs,
        Long lastRequestEpochMs,
        String previousPathSha256
) {
}
