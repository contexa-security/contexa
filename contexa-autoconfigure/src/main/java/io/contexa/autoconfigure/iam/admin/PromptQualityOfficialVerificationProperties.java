package io.contexa.autoconfigure.iam.admin;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties("contexa.pqa.official-verification")
public class PromptQualityOfficialVerificationProperties {

    private Duration staleExecutionTimeout = Duration.ofMinutes(15);

    public Duration getStaleExecutionTimeout() {
        return staleExecutionTimeout;
    }

    public void setStaleExecutionTimeout(Duration staleExecutionTimeout) {
        if (staleExecutionTimeout == null || staleExecutionTimeout.isZero() || staleExecutionTimeout.isNegative()) {
            throw new IllegalArgumentException(
                    "contexa.pqa.official-verification.stale-execution-timeout must be positive.");
        }
        this.staleExecutionTimeout = staleExecutionTimeout;
    }
}
