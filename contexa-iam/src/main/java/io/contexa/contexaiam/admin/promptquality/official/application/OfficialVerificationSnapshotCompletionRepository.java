package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationSnapshotCompletionRepository {
    boolean sealedEvidencePackageExists(String packageId, String tenantId);
    boolean completeSnapshotExists(String aggregateRunId);
    boolean actualPromptProblemExists(String packageId, String aggregateRunId, String problemId);
}