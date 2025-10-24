package io.contexa.contexaidentity.security.core.mfa;

public class RecoveryConfig {
    private final String emailOtpEndpoint;
    private final String smsOtpEndpoint;

    public RecoveryConfig(String emailOtpEndpoint, String smsOtpEndpoint) {
        this.emailOtpEndpoint = emailOtpEndpoint;
        this.smsOtpEndpoint = smsOtpEndpoint;
    }

    public String getEmailOtpEndpoint() {
        return emailOtpEndpoint;
    }

    public String getSmsOtpEndpoint() {
        return smsOtpEndpoint;
    }
}

