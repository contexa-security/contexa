package io.contexa.sandbox.fullstack.prompt;

import java.time.Instant;
import java.util.Map;

public record SandboxDecisionEnforcementSnapshot(
        String requestId,
        String userId,
        String enforcedAction,
        boolean successful,
        Instant completedAt,
        Map<String, Object> metadata) {
}
