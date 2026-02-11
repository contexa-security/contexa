package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "result.delivery")
public class ResultDeliveryProperties {
    @NestedConfigurationProperty
    private RetrySettings retry = new RetrySettings();
    private int ttlHours = 24;
    @NestedConfigurationProperty
    private BatchSettings batch = new BatchSettings();
    @NestedConfigurationProperty
    private WebsocketSettings websocket = new WebsocketSettings();
    @NestedConfigurationProperty
    private NotificationSettings notification = new NotificationSettings();
    @NestedConfigurationProperty
    private EventSettings event = new EventSettings();

    @Data
    public static class RetrySettings {
        private int maxAttempts = 3;
        private int delaySeconds = 5;
    }
    @Data
    public static class BatchSettings {
        private int size = 50;
        private int intervalMs = 1000;
    }
    @Data
    public static class WebsocketSettings {
        private boolean enabled = true;
    }
    @Data
    public static class NotificationSettings {
        private boolean enabled = true;
    }
    @Data
    public static class EventSettings {
        private boolean enabled = true;
    }
}
