package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationCustomerDisplayIntegrityRepository {
    void assertPayloadComplete(String aggregateRunId);
    void assertContractRole(String purposeVersion, String metricCode, String checkCode, String displayRole);
    boolean contractedPromptSignal(String item);
}