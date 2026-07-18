package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationSnapshotCleanupRepository {

    void deleteDiagnosticPackage(String tenantId, String packageId);

    void deleteAggregateSnapshot(String tenantId, String packageId, String aggregateRunId);
}
