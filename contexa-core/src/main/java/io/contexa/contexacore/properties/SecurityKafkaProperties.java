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

import io.contexa.contexacommon.store.ApplicationNamespace;
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

    /**
     * The names of Contexa's topics. A name set here is used exactly as it is set. A name left unset is the default in the
     * namespace of the application, {@code ctxa.<spring.application.name>.} and the default ({@code ctxa.} and the
     * default without a name of the application), which is read when the name is used.
     */
    @Data
    public static class TopicSettings {
        /** Default {@code ctxa.<application>.security-authorization-events}. */
        private String authorization;
        /** Default {@code ctxa.<application>.auth-events}. */
        private String authentication;
        /** Default {@code ctxa.<application>.security-incident-events}. */
        private String incident;
        /** Default {@code ctxa.<application>.threat-indicators}. */
        private String threat;
        /** Default {@code ctxa.<application>.security-audit-events}. */
        private String audit;
        /** Default {@code ctxa.<application>.security-events}. */
        private String general;
        /** The dead letters of security events. Default {@code ctxa.<application>.security-events-dlq}. */
        private String dlq;
        /** Default {@code ctxa.<application>.soar-action-events}. */
        private String soarAction;

        public String getAuthorization() {
            return authorization != null ? authorization : ApplicationNamespace.topic("security-authorization-events");
        }

        public String getAuthentication() {
            return authentication != null ? authentication : ApplicationNamespace.topic("auth-events");
        }

        public String getIncident() {
            return incident != null ? incident : ApplicationNamespace.topic("security-incident-events");
        }

        public String getThreat() {
            return threat != null ? threat : ApplicationNamespace.topic("threat-indicators");
        }

        public String getAudit() {
            return audit != null ? audit : ApplicationNamespace.topic("security-audit-events");
        }

        public String getGeneral() {
            return general != null ? general : ApplicationNamespace.topic("security-events");
        }

        public String getDlq() {
            return dlq != null ? dlq : ApplicationNamespace.topic("security-events-dlq");
        }

        public String getSoarAction() {
            return soarAction != null ? soarAction : ApplicationNamespace.topic("soar-action-events");
        }
    }

    @Data
    public static class DlqSettings {
        private int maxRetries = 3;
        private int retryDelayMs = 5000;
        private int alertThreshold = 10;
    }
}
