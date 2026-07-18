package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationRunBatchWriter {

    void insert(RunBatchCommand command);

    record RunBatchCommand(
            String aggregateRunId,
            String packageId,
            String tenantId,
            String certificateId,
            String caseId,
            MetricCounts metricCounts,
            String finalDecision,
            boolean blocked,
            String blockReasonSummary,
            EvidenceIdentity evidenceIdentity) {
    }

    record MetricCounts(
            int total,
            int passed,
            int failed,
            int insufficient,
            int notApplicable) {
    }

    record EvidenceIdentity(
            String promptHash,
            String contextHash,
            String contextHashState,
            String templateResourceId,
            String actualResourceId,
            String resourceUrlTemplate,
            String actualRequestPath,
            String httpMethod) {
    }
}
