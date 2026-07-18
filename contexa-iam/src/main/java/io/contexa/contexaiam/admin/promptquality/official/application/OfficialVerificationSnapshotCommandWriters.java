package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.Objects;

public final class OfficialVerificationSnapshotCommandWriters {

    private final OfficialVerificationAuditSnapshotWriter auditSnapshotWriter;
    private final OfficialVerificationRunBatchWriter runBatchWriter;
    private final OfficialVerificationMetricSnapshotWriter metricSnapshotWriter;
    private final OfficialVerificationFindingWriter findingWriter;
    private final OfficialVerificationRemediationGroupWriter remediationGroupWriter;
    private final OfficialVerificationPromptComparisonWriter promptComparisonWriter;
    private final OfficialPromptFieldDefinitionWriter promptFieldDefinitionWriter;
    private final OfficialVerificationExecutionWriters executionWriters;

    public OfficialVerificationSnapshotCommandWriters(
            OfficialVerificationAuditSnapshotWriter auditSnapshotWriter,
            OfficialVerificationRunBatchWriter runBatchWriter,
            OfficialVerificationMetricSnapshotWriter metricSnapshotWriter,
            OfficialVerificationFindingWriter findingWriter,
            OfficialVerificationRemediationGroupWriter remediationGroupWriter,
            OfficialVerificationPromptComparisonWriter promptComparisonWriter,
            OfficialPromptFieldDefinitionWriter promptFieldDefinitionWriter,
            OfficialVerificationExecutionWriters executionWriters) {
        this.auditSnapshotWriter = Objects.requireNonNull(auditSnapshotWriter, "auditSnapshotWriter");
        this.runBatchWriter = Objects.requireNonNull(runBatchWriter, "runBatchWriter");
        this.metricSnapshotWriter = Objects.requireNonNull(metricSnapshotWriter, "metricSnapshotWriter");
        this.findingWriter = Objects.requireNonNull(findingWriter, "findingWriter");
        this.remediationGroupWriter = Objects.requireNonNull(remediationGroupWriter, "remediationGroupWriter");
        this.promptComparisonWriter = Objects.requireNonNull(promptComparisonWriter, "promptComparisonWriter");
        this.promptFieldDefinitionWriter = Objects.requireNonNull(promptFieldDefinitionWriter, "promptFieldDefinitionWriter");
        this.executionWriters = Objects.requireNonNull(executionWriters, "executionWriters");
    }

    public OfficialVerificationAuditSnapshotWriter auditSnapshot() { return auditSnapshotWriter; }
    public OfficialVerificationRunBatchWriter runBatch() { return runBatchWriter; }
    public OfficialVerificationMetricSnapshotWriter metricSnapshot() { return metricSnapshotWriter; }
    public OfficialVerificationFindingWriter finding() { return findingWriter; }
    public OfficialVerificationRemediationGroupWriter remediationGroup() { return remediationGroupWriter; }
    public OfficialVerificationPromptComparisonWriter promptComparison() { return promptComparisonWriter; }
    public OfficialPromptFieldDefinitionWriter promptFieldDefinition() { return promptFieldDefinitionWriter; }
    public OfficialVerificationExecutionWriters execution() { return executionWriters; }
}