package io.contexa.contexacore.autonomous.execution;

import java.time.LocalDateTime;

public record DelegatedExecutionGraph(
        String executionKey,
        String executionFingerprint,
        String tenantId,
        String clientId,
        boolean serviceClientPrincipal,
        DelegatedExecutionContext context,
        String capability,
        String operation,
        String sourcePath,
        String httpMethod,
        String resourceFingerprint,
        String requestFingerprint,
        LocalDateTime observedAt,
        LocalDateTime expiresAt) {
}