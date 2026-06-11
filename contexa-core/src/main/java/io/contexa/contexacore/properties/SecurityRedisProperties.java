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
@ConfigurationProperties(prefix = "contexa.security.redis")
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
