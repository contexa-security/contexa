package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationCurrentResultCoordinator {

    void acquireWriteLock(
            String packageId,
            String tenantId,
            String requestPath,
            String resourceId,
            String httpMethod);

    void supersedeCurrent(
            String aggregateRunId,
            String tenantId,
            String requestPath,
            String resourceId,
            String httpMethod);
}