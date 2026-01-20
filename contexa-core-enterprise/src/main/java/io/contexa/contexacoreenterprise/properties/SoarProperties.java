package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


@Data
@ConfigurationProperties(prefix = "soar")
public class SoarProperties {

    
    private double similarityThreshold = 0.75;

    
    private int topK = 20;

    
    private int lookbackHours = 24;

    
    @NestedConfigurationProperty
    private ApprovalSettings approval = new ApprovalSettings();

    
    @NestedConfigurationProperty
    private NotificationSettings notification = new NotificationSettings();

    
    @Data
    public static class ApprovalSettings {
        private boolean enabled = true;
        private int order = 100;
        private int timeout = 300;
    }

    
    @Data
    public static class NotificationSettings {
        @NestedConfigurationProperty
        private EmailSettings email = new EmailSettings();

        @NestedConfigurationProperty
        private WebSocketSettings websocket = new WebSocketSettings();

        @NestedConfigurationProperty
        private SseSettings sse = new SseSettings();

        @Data
        public static class EmailSettings {
            private boolean enabled = true;
            private String baseUrl = "http://localhost:8080";
        }

        @Data
        public static class WebSocketSettings {
            private boolean enabled = true;
            private String topicPrefix = "/topic/soar";
        }

        @Data
        public static class SseSettings {
            private boolean enabled = true;
        }
    }
}
