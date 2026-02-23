package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "soar")
public class SoarProperties {

    private double similarityThreshold = 0.75;

    private int topK = 20;

    @NestedConfigurationProperty
    private ApprovalSettings approval = new ApprovalSettings();

    @NestedConfigurationProperty
    private ToolExecutionSettings toolExecution = new ToolExecutionSettings();

    @NestedConfigurationProperty
    private NotificationSettings notification = new NotificationSettings();

    @Data
    public static class ApprovalSettings {
        private int timeout = 300;
    }

    @Data
    public static class ToolExecutionSettings {
        private int maxIterations = 10;
        private long timeoutMs = 30000;
        private int llmTimeoutSeconds = 30;
        private int contextExpiryMinutes = 30;
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
