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
@ConfigurationProperties(prefix = "contexa.security.kafka")
public class SecurityKafkaProperties {

    @NestedConfigurationProperty
    private TopicSettings topic = new TopicSettings();

    @NestedConfigurationProperty
    private DlqSettings dlq = new DlqSettings();

    @Data
    public static class TopicSettings {
        private String authorization = "security-authorization-events";
        private String authentication = "auth-events";
        private String incident = "security-incident-events";
        private String threat = "threat-indicators";
        private String audit = "security-audit-events";
        private String general = "security-events";
        private String dlq = "security-events-dlq";
        private String soarAction = "soar-action-events";
    }

    @Data
    public static class DlqSettings {
        private int maxRetries = 3;
        private int retryDelayMs = 5000;
        private int alertThreshold = 10;
    }
}
