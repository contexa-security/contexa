package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


/**
 * Security Pipeline 설정
 */
@Data
@ConfigurationProperties(prefix = "security.pipeline")
public class SecurityPipelineProperties {

    /**
     * Redis 설정
     */
    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    /**
     * Kafka 설정
     */
    @NestedConfigurationProperty
    private KafkaSettings kafka = new KafkaSettings();

    /**
     * Redis 설정
     */
    @Data
    public static class RedisSettings {
        private String streamKey = "security-events-stream";
        private String consumerGroup = "security-simulation-consumers";
    }

    /**
     * Kafka 설정
     */
    @Data
    public static class KafkaSettings {
        private String topic = "security-events";
    }
}
