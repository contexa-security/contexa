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
        // Stream 관련 설정 제거됨 (Dead Code - Consumer 없음)
    }

    /**
     * Kafka 설정
     */
    @Data
    public static class KafkaSettings {
        private String topic = "security-events";
    }
}
