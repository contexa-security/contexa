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
@ConfigurationProperties(prefix = "contexa.security.event")
public class SecurityEventProperties {

    @NestedConfigurationProperty
    private PublishingSettings publishing = new PublishingSettings();

    @NestedConfigurationProperty
    private ExecutorSettings executor = new ExecutorSettings();

    @NestedConfigurationProperty
    private TierSettings tier = new TierSettings();

    @NestedConfigurationProperty
    private DeduplicationSettings deduplication = new DeduplicationSettings();

    @Data
    public static class PublishingSettings {
        private boolean enabled = true;
        private String excludeUris = "/actuator,/health,/metrics";

        @NestedConfigurationProperty
        private AnonymousSettings anonymous = new AnonymousSettings();

        @Data
        public static class AnonymousSettings {
            private boolean enabled = true;
        }
    }

    @Data
    public static class ExecutorSettings {
        private int corePoolSize = Runtime.getRuntime().availableProcessors() * 2;
        private int maxPoolSize = Runtime.getRuntime().availableProcessors() * 4;
        private int queueCapacity = 10000;
    }

    @Data
    public static class TierSettings {
        @NestedConfigurationProperty
        private CriticalSettings critical = new CriticalSettings();

        @NestedConfigurationProperty
        private ContextualSettings contextual = new ContextualSettings();

        @NestedConfigurationProperty
        private GeneralSettings general = new GeneralSettings();

        @Data
        public static class CriticalSettings {
            private int maxLatencyMs = 100;
        }

        @Data
        public static class ContextualSettings {
            private int maxLatencyMs = 1000;
        }

        @Data
        public static class GeneralSettings {
            private int maxLatencyMs = 10000;
            private double samplingRate = 0.1;
        }
    }

    @Data
    public static class DeduplicationSettings {
        private int windowMinutes = 5;
        private int cacheSize = 10000;
        private boolean enabled = true;
    }
}
