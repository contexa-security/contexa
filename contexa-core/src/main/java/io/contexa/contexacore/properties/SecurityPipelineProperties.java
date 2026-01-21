package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "security.pipeline")
public class SecurityPipelineProperties {

    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    @NestedConfigurationProperty
    private KafkaSettings kafka = new KafkaSettings();

    @Data
    public static class RedisSettings {
        
    }

    @Data
    public static class KafkaSettings {
        private String topic = "security-events";
    }
}
