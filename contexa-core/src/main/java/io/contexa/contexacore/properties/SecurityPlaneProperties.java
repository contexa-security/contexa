package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "security.plane")
public class SecurityPlaneProperties {

    @NestedConfigurationProperty
    private AgentSettings agent = new AgentSettings();

    @NestedConfigurationProperty
    private KafkaSettings kafka = new KafkaSettings();

    @NestedConfigurationProperty
    private MonitorSettings monitor = new MonitorSettings();

    @NestedConfigurationProperty
    private NotifierSettings notifier = new NotifierSettings();

    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    @NestedConfigurationProperty
    private LlmExecutorSettings llmExecutor = new LlmExecutorSettings();

    @NestedConfigurationProperty
    private DeduplicationSettings deduplication = new DeduplicationSettings();

    @Data
    public static class AgentSettings {
        private String name = "SecurityPlaneAgent-1";
        private boolean autoStart = true;
        private double threatThreshold = 0.7;

        private String organizationId = "default-org";
        private String executionMode = "ASYNC";
    }

    @Data
    public static class KafkaSettings {
        private String bootstrapServers = "localhost:9092";
        private String groupId = "security-plane-consumer";

        @NestedConfigurationProperty
        private TopicsSettings topics = new TopicsSettings();

        @Data
        public static class TopicsSettings {
            private String securityEvents = "security-events";
            private String threatIndicators = "threat-indicators";
            private String networkEvents = "network-events";
            private String authEvents = "auth-events";
        }
    }

    @Data
    public static class MonitorSettings {
        private int queueSize = 10000;
        private int workerThreads = 5;
        private int correlationWindowMinutes = 10;

        private int dedupWindowMinutes = 5;
    }

    @Data
    public static class NotifierSettings {
        private int batchSize = 10;
        private boolean asyncEnabled = true;

    }

    @Data
    public static class RedisSettings {
        private int batchSize = 50;

        @NestedConfigurationProperty
        private CacheSettings cache = new CacheSettings();

        @NestedConfigurationProperty
        private ChannelSettings channel = new ChannelSettings();

        @Data
        public static class CacheSettings {
            private int ttlMinutes = 60;
        }

        @Data
        public static class ChannelSettings {
            private String securityEvents = "security:events";
            private String threatAlerts = "security:threats";
        }
    }

    @Data
    public static class LlmExecutorSettings {

        private int corePoolSize = 10;

        private int maxPoolSize = 10;

        private int queueCapacity = 1000;
    }

    @Data
    public static class DeduplicationSettings {

        private boolean enabled = true;

        private int windowMinutes = 5;

        private int cacheSize = 10000;
    }
}
