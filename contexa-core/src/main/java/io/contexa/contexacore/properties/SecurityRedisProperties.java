package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "security.redis")
public class SecurityRedisProperties {

    @NestedConfigurationProperty
    private ChannelSettings channel = new ChannelSettings();

    @NestedConfigurationProperty
    private StreamSettings stream = new StreamSettings();

    @NestedConfigurationProperty
    private TtlSettings ttl = new TtlSettings();

    @NestedConfigurationProperty
    private MemorySettings memory = new MemorySettings();

    @Data
    public static class ChannelSettings {
        private String authorization = "security:authorization:events";
        private String authentication = "security:events";
        private String incident = "security:incidents";
        private String threat = "security:threats";
        private String audit = "security:audit:events";
        private String general = "security:events";
    }

    @Data
    public static class StreamSettings {
        private String authorization = "security:stream:authorization";
        private String incident = "security:stream:incident";
        private String threat = "security:stream:threat";
        private String audit = "security:stream:audit";
        private String general = "security:stream:general";
        private String authentication = "security:stream:authentication";
        private int maxlen = 10000;
    }

    @Data
    public static class TtlSettings {
        private int minutes = 60;
    }

    @Data
    public static class MemorySettings {
        private int maxMb = 1024;
        private double warningThreshold = 0.8;
        private double criticalThreshold = 0.9;
    }
}
