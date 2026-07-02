/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "contexa.security.plane")
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
    private LlmTimeoutSettings llmTimeout = new LlmTimeoutSettings();

    @NestedConfigurationProperty
    private LlmProviderThrottleSettings llmProviderThrottle = new LlmProviderThrottleSettings();

    @NestedConfigurationProperty
    private DeduplicationSettings deduplication = new DeduplicationSettings();

    @Data
    public static class AgentSettings {
        private String name = "SecurityPlaneAgent-1";
        private boolean autoStart = true;

        private String organizationId = "default-org";
        private String executionMode = "ASYNC";
        private boolean autoApproveLowRisk = false;
        private long eventTimeoutMs = 180000L;
        private int maxDeferredRetries = 3;
        private int analysisStripes = 256;
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
        private int batchSize = 8;
        private long flushIntervalMs = 500;
        private int correlationWindowMinutes = 10;

        private int dedupWindowMinutes = 5;
    }

    @Data
    public static class NotifierSettings {
        private int batchSize = 10;
        private boolean asyncEnabled = true;
        private double criticalThreshold = 0.8;
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

        private int corePoolSize = 32;

        private int maxPoolSize = 64;

        private int queueCapacity = 256;

        private long queueTimeoutMs = 60000L;

        private boolean prestartCoreThreads = true;
    }

    @Data
    public static class LlmTimeoutSettings {

        private long providerCallTimeoutMs = 60000L;
    }

    @Data
    public static class LlmProviderThrottleSettings {

        private boolean enabled = false;

        private boolean openAiOnly = true;

        private int requestsPerMinute = 0;

        private int tokensPerMinute = 0;

        private int maxBurstRequests = 0;

        private int maxBurstTokens = 0;

        private int estimatedOutputTokens = 1024;

        private long maxWaitMs = 120000L;
    }

    @Data
    public static class DeduplicationSettings {

        private boolean enabled = true;

        private int windowMinutes = 5;

        private int cacheSize = 10000;
    }
}


