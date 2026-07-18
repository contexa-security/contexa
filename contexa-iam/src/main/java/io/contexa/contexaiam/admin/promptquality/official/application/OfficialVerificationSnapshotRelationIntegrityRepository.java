package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationSnapshotRelationIntegrityRepository {
    void assertMetricSnapshotComplete(String aggregateRunId);
    void assertPromptComparisonLinksComplete(String aggregateRunId);
    void assertActualPromptProblemLedgerAligned(String aggregateRunId);
    void assertPromptFieldDefinitionsCoverStateLedger(String aggregateRunId);
}