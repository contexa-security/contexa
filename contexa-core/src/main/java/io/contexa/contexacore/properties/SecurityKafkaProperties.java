package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Security Kafka 설정
 */
@Data
@ConfigurationProperties(prefix = "security.kafka")
public class SecurityKafkaProperties {

    /**
     * 토픽 설정
     */
    @NestedConfigurationProperty
    private TopicSettings topic = new TopicSettings();

    /**
     * DLQ 설정
     */
    @NestedConfigurationProperty
    private DlqSettings dlq = new DlqSettings();

    /**
     * 토픽 설정
     */
    @Data
    public static class TopicSettings {
        private String authorization = "security-authorization-events";
        private String authentication = "auth-events";
        private String incident = "security-incident-events";
        private String threat = "threat-indicators";
        private String audit = "security-audit-events";
        private String general = "security-events";
        private String dlq = "security-events-dlq";
    }

    /**
     * DLQ (Dead Letter Queue) 설정
     */
    @Data
    public static class DlqSettings {
        private int maxRetries = 3;
        private int retryDelayMs = 5000;
        private int alertThreshold = 10;
    }
}
