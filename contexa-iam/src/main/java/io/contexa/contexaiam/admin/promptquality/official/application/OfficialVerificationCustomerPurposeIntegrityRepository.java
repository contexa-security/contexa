package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationCustomerPurposeIntegrityRepository {
    void assertClean(String aggregateRunId);
}