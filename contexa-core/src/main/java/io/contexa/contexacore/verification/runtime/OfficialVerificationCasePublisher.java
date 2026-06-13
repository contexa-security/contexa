package io.contexa.contexacore.verification.runtime;

public interface OfficialVerificationCasePublisher {

    void register(String userId, OfficialVerificationRunRecord record);
}
