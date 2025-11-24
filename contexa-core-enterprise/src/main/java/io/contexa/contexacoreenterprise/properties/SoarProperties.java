package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * SOAR (Security Orchestration, Automation and Response) 설정
 */
@Data
@ConfigurationProperties(prefix = "soar")
public class SoarProperties {

    /**
     * 유사도 임계값
     */
    private double similarityThreshold = 0.75;

    /**
     * Top-K 결과 수
     */
    private int topK = 20;

    /**
     * Lookback 시간 (hours)
     */
    private int lookbackHours = 24;

    /**
     * 승인 설정
     */
    @NestedConfigurationProperty
    private ApprovalSettings approval = new ApprovalSettings();

    /**
     * 알림 설정
     */
    @NestedConfigurationProperty
    private NotificationSettings notification = new NotificationSettings();

    /**
     * 승인 설정
     */
    @Data
    public static class ApprovalSettings {
        private boolean enabled = true;
        private int order = 100;
        private int timeout = 300;
    }

    /**
     * 알림 설정
     */
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
