package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationActualPromptProblemLinker {

    void link(String aggregateRunId, String packageId, String tenantId);
}
