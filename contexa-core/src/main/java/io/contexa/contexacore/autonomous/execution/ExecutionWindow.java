package io.contexa.contexacore.autonomous.execution;

import java.time.LocalDateTime;

public record ExecutionWindow(
        LocalDateTime startedAt,
        LocalDateTime expiresAt) {

    public boolean timeBound() {
        return startedAt != null || expiresAt != null;
    }
}