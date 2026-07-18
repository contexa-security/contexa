package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationMetricPurposeEvidenceWriter {

    void insert(Command command);

    record Command(
            String packageId,
            String aggregateRunId,
            String metricCode,
            String checkCode,
            String contractVersion,
            String signalKey,
            String promptLocation,
            String evidenceValue,
            String evidenceHash,
            String interpretation,
            String purposeResult,
            boolean customerVisible,
            String readinessScope,
            String runtimeFactsJson,
            String contextItemsJson) {
    }
}
