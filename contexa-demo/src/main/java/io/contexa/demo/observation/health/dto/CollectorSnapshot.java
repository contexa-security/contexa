package io.contexa.demo.observation.health.dto;

import java.time.Instant;
import java.util.UUID;

public record CollectorSnapshot(
        UUID instanceId,
        String source,
        Instant startedAt,
        Instant sampledAt,
        String lifecycle,
        long offered,
        long stored,
        long rejected,
        long writeUnconfirmed,
        long abandoned,
        long pending,
        long inFlight) {

    public long missingCount() {
        return rejected + writeUnconfirmed + abandoned;
    }
}
