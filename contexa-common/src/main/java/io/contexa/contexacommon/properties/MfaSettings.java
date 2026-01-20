package io.contexa.contexacommon.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.time.Duration;
import java.util.concurrent.TimeUnit;


@Getter
@Setter
public class MfaSettings {

    
    
    @NestedConfigurationProperty
    private MfaUrls urls = new MfaUrls();

    
    
    private long sessionTimeoutMs = TimeUnit.MINUTES.toMillis(10);

    
    private long challengeTimeoutMs = TimeUnit.MINUTES.toMillis(5);
    private long inactivityTimeout = TimeUnit.MINUTES.toMillis(15);
    private long cacheTtl = TimeUnit.MINUTES.toMillis(5);

    
    private long sessionRefreshIntervalMs = TimeUnit.SECONDS.toMillis(30);

    
    private long stateMachineTimeoutMs = TimeUnit.SECONDS.toMillis(10);

    
    
    private int maxRetryAttempts = 5;

    
    private long accountLockoutDurationMs = TimeUnit.MINUTES.toMillis(15);

    
    private long minimumDelayMs = 500L;

    
    private long deviceRememberDurationMs = TimeUnit.DAYS.toMillis(30);

    
    
    private int otpTokenValiditySeconds = 300; 

    
    private int otpTokenLength = 6;

    
    private int smsResendIntervalSeconds = 60;

    
    private int emailResendIntervalSeconds = 120;

    
    
    private int stateMachinePoolSize = 100;

    
    private long stateMachineCacheTtlMs = TimeUnit.MINUTES.toMillis(5);

    
    private int circuitBreakerFailureThreshold = 5;

    
    private int circuitBreakerTimeoutSeconds = 30;

    
    
    private boolean detailedLoggingEnabled = false;

    
    private boolean metricsEnabled = true;

    
    private boolean auditLoggingEnabled = true;

    
    private String sessionStorageType = "http-session";

    
    private boolean autoSelectRepository = false;

    
    private String repositoryPriority = "redis,memory,http-session";

    
    private String fallbackRepositoryType = "http-session";

    

    @NestedConfigurationProperty
    private HttpSessionSettings httpSession = new HttpSessionSettings();

    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    @NestedConfigurationProperty
    private MemorySettings memory = new MemorySettings();

    
    @NestedConfigurationProperty
    private SmsFactorSettings smsFactor = new SmsFactorSettings();

    
    @NestedConfigurationProperty
    private EmailFactorSettings emailFactor = new EmailFactorSettings();

    

    
    public Duration getSessionTimeout() {
        return Duration.ofMillis(sessionTimeoutMs);
    }

    
    public Duration getChallengeTimeout() {
        return Duration.ofMillis(challengeTimeoutMs);
    }

    
    public Duration getAccountLockoutDuration() {
        return Duration.ofMillis(accountLockoutDurationMs);
    }

    
    public Duration getDeviceRememberDuration() {
        return Duration.ofMillis(deviceRememberDurationMs);
    }

    
    public Duration getOtpTokenValidity() {
        return Duration.ofSeconds(otpTokenValiditySeconds);
    }

    
    public Duration getStateMachineTimeout() {
        return Duration.ofMillis(stateMachineTimeoutMs);
    }

    
    public boolean isSessionExpired(java.time.Instant lastActivityTime) {
        return java.time.Instant.now().isAfter(lastActivityTime.plusMillis(sessionTimeoutMs));
    }

    
    public boolean isSessionExpired(long lastActivityTimeMs) {
        return (System.currentTimeMillis() - lastActivityTimeMs) > sessionTimeoutMs;
    }

    
    public boolean isChallengeExpired(java.time.Instant challengeStartTime) {
        return java.time.Instant.now().isAfter(challengeStartTime.plusMillis(challengeTimeoutMs));
    }

    
    public boolean isChallengeExpired(long challengeStartTimeMs) {
        return (System.currentTimeMillis() - challengeStartTimeMs) > challengeTimeoutMs;
    }

    
    public boolean needsSessionRefresh(java.time.Instant lastRefreshTime) {
        return java.time.Instant.now().isAfter(lastRefreshTime.plusMillis(sessionRefreshIntervalMs));
    }

    
    public java.time.Instant calculateSessionExpiry(java.time.Instant lastActivityTime) {
        return lastActivityTime.plusMillis(sessionTimeoutMs);
    }

    
    public long calculateSessionExpiry(long lastActivityTimeMs) {
        return lastActivityTimeMs + sessionTimeoutMs;
    }

    
    public java.time.Instant calculateChallengeExpiry(java.time.Instant challengeStartTime) {
        return challengeStartTime.plusMillis(challengeTimeoutMs);
    }

    
    public boolean isRetryAllowed(int currentAttempts) {
        return currentAttempts < maxRetryAttempts;
    }

    
    public boolean needsSessionRefresh(long lastRefreshTime) {
        return (System.currentTimeMillis() - lastRefreshTime) > sessionRefreshIntervalMs;
    }

    
    public boolean canResendSms(long lastSentTime) {
        return (System.currentTimeMillis() - lastSentTime) > (smsResendIntervalSeconds * 1000L);
    }

    
    public boolean canResendEmail(long lastSentTime) {
        return (System.currentTimeMillis() - lastSentTime) > (emailResendIntervalSeconds * 1000L);
    }

    
    public void validate() {
        if (sessionTimeoutMs <= 0) {
            throw new IllegalStateException("Session timeout must be positive");
        }

        if (challengeTimeoutMs <= 0) {
            throw new IllegalStateException("Challenge timeout must be positive");
        }

        if (challengeTimeoutMs > sessionTimeoutMs) {
            throw new IllegalStateException("Challenge timeout cannot be greater than session timeout");
        }

        if (maxRetryAttempts <= 0) {
            throw new IllegalStateException("Max retry attempts must be positive");
        }

        if (otpTokenValiditySeconds <= 0) {
            throw new IllegalStateException("OTP token validity must be positive");
        }

        if (otpTokenLength < 4 || otpTokenLength > 12) {
            throw new IllegalStateException("OTP token length must be between 4 and 12");
        }

        if (stateMachinePoolSize <= 0) {
            throw new IllegalStateException("State machine pool size must be positive");
        }
    }

    
    public String getDebugInfo() {
        return String.format("""
            MfaSettings Debug Info:
            - Session Timeout: %d ms (%s)
            - Challenge Timeout: %d ms (%s)
            - Max Retry Attempts: %d
            - OTP Validity: %d seconds
            - State Machine Pool Size: %d
            - Circuit Breaker Threshold: %d
            - Detailed Logging: %s
            - Metrics Enabled: %s
            - Audit Logging: %s
            """,
                sessionTimeoutMs, getSessionTimeout(),
                challengeTimeoutMs, getChallengeTimeout(),
                maxRetryAttempts,
                otpTokenValiditySeconds,
                stateMachinePoolSize,
                circuitBreakerFailureThreshold,
                detailedLoggingEnabled,
                metricsEnabled,
                auditLoggingEnabled
        );
    }
}


@Getter
@Setter
class SmsFactorSettings {
    private String provider = "default";
    private String templateId = "mfa_sms_template";
    private int maxDailyAttempts = 10;
    private boolean enabled = true;
}


@Getter
@Setter
class EmailFactorSettings {
    private String fromAddress = "noreply@company.com";
    private String templateId = "mfa_email_template";
    private int maxDailyAttempts = 5;
    private boolean enabled = true;
}


@Getter
@Setter
class HttpSessionSettings {
    private boolean enabled = true;
    private boolean createSessionIfNotExists = true;
    private String sessionAttributeName = "MFA_SESSION_ID";
}


@Getter
@Setter
class RedisSettings {
    private boolean enabled = true;
    private String keyPrefix = "mfa:session:";
    private String cookieName = "MFA_SID";
    private boolean secureCookie = true;
    private boolean httpOnlyCookie = true;
    private String sameSite = "Strict";
    private int connectionTimeout = 3000;
    private int maxRetries = 3;
}


@Getter
@Setter
class MemorySettings {
    private boolean enabled = true;
    private int cleanupIntervalMinutes = 5;
    private int maxSessions = 10000;
    private boolean enableMetrics = true;
}