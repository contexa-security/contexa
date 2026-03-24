package io.contexa.contexacore.autonomous.execution;


import java.time.LocalDateTime;

public class DelegatedExecutionGraphBuilder {

    private final DelegatedExecutionFingerprintService delegatedExecutionFingerprintService;

    public DelegatedExecutionGraphBuilder(DelegatedExecutionFingerprintService delegatedExecutionFingerprintService) {
        this.delegatedExecutionFingerprintService = delegatedExecutionFingerprintService != null
                ? delegatedExecutionFingerprintService
                : new DelegatedExecutionFingerprintService();
    }

    public DelegatedExecutionGraph build(
            String tenantId,
            String clientId,
            boolean serviceClientPrincipal,
            DelegatedExecutionContext context,
            String capability,
            String operation,
            String sourcePath,
            String httpMethod,
            String resourceFingerprint,
            LocalDateTime observedAt) {
        String requestFingerprint = delegatedExecutionFingerprintService.computeRequestFingerprint(httpMethod, sourcePath, resourceFingerprint);
        String executionKey = delegatedExecutionFingerprintService.resolveExecutionKey(
                tenantId,
                clientId,
                context,
                capability,
                operation,
                resourceFingerprint,
                requestFingerprint);
        String executionFingerprint = delegatedExecutionFingerprintService.computeExecutionFingerprint(
                tenantId,
                clientId,
                context,
                capability,
                operation,
                resourceFingerprint,
                requestFingerprint);
        LocalDateTime effectiveObservedAt = observedAt != null ? observedAt : LocalDateTime.now();
        return new DelegatedExecutionGraph(
                executionKey,
                executionFingerprint,
                tenantId,
                clientId,
                serviceClientPrincipal,
                context,
                capability,
                operation,
                sourcePath,
                httpMethod,
                resourceFingerprint,
                requestFingerprint,
                effectiveObservedAt,
                context != null ? context.expiresAt() : null);
    }
}