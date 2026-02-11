package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "sms")
public class SmsProperties {
    private String provider = "TWILIO";
    @NestedConfigurationProperty
    private ApiSettings api = new ApiSettings();
    @NestedConfigurationProperty
    private SenderSettings sender = new SenderSettings();
    @NestedConfigurationProperty
    private MaxSettings max = new MaxSettings();
    @NestedConfigurationProperty
    private RetrySettings retry = new RetrySettings();
    @NestedConfigurationProperty
    private RateLimitSettings rateLimit = new RateLimitSettings();
    private boolean enabled = false;
    private boolean emergencyOnly = true;

    @Data
    public static class ApiSettings {
        private String url = "";
        private String key = "";
        private String secret = "";
    }
    @Data
    public static class SenderSettings {
        private String number = "";
        private String id = "contexa";
    }
    @Data
    public static class MaxSettings {
        private int length = 140;
    }
    @Data
    public static class RetrySettings {
        private int maxAttempts = 2;
        private int delaySeconds = 3;
    }
    @Data
    public static class RateLimitSettings {
        private int messagesPerHour = 100;
    }
}
