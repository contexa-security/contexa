package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Security Plane Agent 설정
 */
@Data
@ConfigurationProperties(prefix = "security.plane")
public class SecurityPlaneProperties {

    /**
     * 에이전트 설정
     */
    @NestedConfigurationProperty
    private AgentSettings agent = new AgentSettings();

    /**
     * Kafka 설정
     */
    @NestedConfigurationProperty
    private KafkaSettings kafka = new KafkaSettings();

    /**
     * 모니터 설정
     */
    @NestedConfigurationProperty
    private MonitorSettings monitor = new MonitorSettings();

    /**
     * 알림 설정
     */
    @NestedConfigurationProperty
    private NotifierSettings notifier = new NotifierSettings();

    /**
     * Redis 설정
     */
    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    /**
     * 에이전트 설정
     */
    @Data
    public static class AgentSettings {
        private String name = "SecurityPlaneAgent-1";
        private boolean autoStart = true;
        private int maxConcurrentIncidents = 10;
        private double threatThreshold = 0.7;
        private double similarityThreshold = 0.70;
        private double layer1Threshold = 0.55;
        private double layer2Threshold = 0.40;
        private String organizationId = "default-org";
        private String executionMode = "ASYNC";
        private boolean autoApproveLowRisk = false;
    }

    /**
     * Kafka 설정
     */
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

    /**
     * 모니터 설정
     */
    @Data
    public static class MonitorSettings {
        private int queueSize = 10000;
        private int workerThreads = 5;
        private int correlationWindowMinutes = 10;
        private double threatThreshold = 0.7;
        private boolean autoIncidentCreation = true;
        private int dedupWindowMinutes = 5;
    }

    /**
     * 알림 설정
     */
    @Data
    public static class NotifierSettings {
        private int batchSize = 10;
        private boolean asyncEnabled = true;
        private double criticalThreshold = 0.8;
    }

    /**
     * Redis 설정
     */
    @Data
    public static class RedisSettings {
        private int batchSize = 50;

        @NestedConfigurationProperty
        private CacheSettings cache = new CacheSettings();

        @NestedConfigurationProperty
        private ChannelSettings channel = new ChannelSettings();

        @NestedConfigurationProperty
        private StreamSettings stream = new StreamSettings();

        @Data
        public static class CacheSettings {
            private int ttlMinutes = 60;
        }

        @Data
        public static class ChannelSettings {
            private String securityEvents = "security:events";
            private String threatAlerts = "security:threats";
            private String incidents = "security:incidents";
        }

        @Data
        public static class StreamSettings {
            private String events = "security-events-stream";
        }
    }
}
