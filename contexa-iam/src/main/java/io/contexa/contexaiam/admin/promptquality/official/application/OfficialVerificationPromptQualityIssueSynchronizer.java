package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationPromptQualityIssueSynchronizer {

    void synchronize(String tenantId, String packageId, String aggregateRunId);
}
