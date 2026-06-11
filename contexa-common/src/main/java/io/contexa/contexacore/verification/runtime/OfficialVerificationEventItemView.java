package io.contexa.contexacore.verification.runtime;

public interface OfficialVerificationEventItemView {

    String type();

    String layer();

    String status();

    String requestPath();
}