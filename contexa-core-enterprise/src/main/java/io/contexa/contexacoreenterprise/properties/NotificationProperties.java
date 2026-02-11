package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "notification")
public class NotificationProperties {
    @NestedConfigurationProperty
    private EnabledSettings enabled = new EnabledSettings();
    @NestedConfigurationProperty
    private RetrySettings retry = new RetrySettings();
    @NestedConfigurationProperty
    private PrioritySettings priority = new PrioritySettings();
    @NestedConfigurationProperty
    private BatchSettings batch = new BatchSettings();

    @Data
    public static class EnabledSettings {
        private boolean email = true;
        private boolean websocket = true;
        private boolean slack = false;
        private boolean sms = false;
    }
    @Data
    public static class RetrySettings {
        private int maxAttempts = 3;
        private int delaySeconds = 5;
    }
    @Data
    public static class PrioritySettings {
        private String threshold = "HIGH";
    }
    @Data
    public static class BatchSettings {
        private int size = 100;
        private int delayMs = 1000;
    }
}
