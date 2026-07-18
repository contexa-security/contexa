package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationPromptSignalWriter {

    void insert(Command command);

    record Command(
            String packageId,
            String aggregateRunId,
            String metricCode,
            String checkCode,
            String signalKey,
            String promptLocation,
            String sectionName,
            String labelName,
            String valuePreview,
            String valueHash,
            Integer lineNumber,
            String signalRole) {
    }
}
