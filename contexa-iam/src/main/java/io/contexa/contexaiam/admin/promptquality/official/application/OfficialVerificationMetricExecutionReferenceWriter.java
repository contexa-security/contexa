package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationMetricExecutionReferenceWriter {

    void update(Command command);

    record Command(
            String aggregateRunId,
            String metricCode,
            String packageId,
            String tenantId,
            String issueIdsJson,
            String problemIdsJson) {
    }
}
