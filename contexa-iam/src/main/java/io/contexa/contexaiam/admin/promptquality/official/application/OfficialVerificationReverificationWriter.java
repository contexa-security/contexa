package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationReverificationWriter {

    void replace(String sourcePackageId, String fixedPackageId, String fixedAggregateRunId, String tenantId);

    void insert(Command command);

    record Command(
            String sourcePackageId,
            String sourceAggregateRunId,
            String fixedPackageId,
            String fixedAggregateRunId,
            String findingId,
            String issueId,
            String metricCode,
            String checkCode,
            String reverifyCriterion,
            String sourceOperatorReason,
            String sourceExpectedValue,
            String sourceActualValue,
            String fixedActualValue,
            boolean resolved,
            String resolutionState,
            String operatorSummary,
            String createdBy,
            String diagnosticCatalogVersion) {
    }
}
