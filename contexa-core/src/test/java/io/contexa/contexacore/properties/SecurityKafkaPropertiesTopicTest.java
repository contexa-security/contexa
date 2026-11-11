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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The names of Contexa's topics as the properties give them: a default is in the namespace of the application, and a
 * name the operator set is used exactly as it is set, which is how an installation keeps the names it had.
 */
class SecurityKafkaPropertiesTopicTest {

    /** The properties as Spring Boot binds them from the application's configuration. */
    private static SecurityKafkaProperties.TopicSettings bound(Map<String, String> configuration) {
        return new Binder(new MapConfigurationPropertySource(configuration))
                .bind("contexa.security.kafka", SecurityKafkaProperties.class)
                .orElseGet(SecurityKafkaProperties::new).getTopic();
    }

    @Test
    @DisplayName("every default name is in the application's namespace")
    void theDefaultsAreTheApplications() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            SecurityKafkaProperties.TopicSettings topics = bound(Map.of());

            assertThat(topics.getAuthorization()).isEqualTo("ctxa.shop.security-authorization-events");
            assertThat(topics.getAuthentication()).isEqualTo("ctxa.shop.auth-events");
            assertThat(topics.getIncident()).isEqualTo("ctxa.shop.security-incident-events");
            assertThat(topics.getThreat()).isEqualTo("ctxa.shop.threat-indicators");
            assertThat(topics.getAudit()).isEqualTo("ctxa.shop.security-audit-events");
            assertThat(topics.getGeneral()).isEqualTo("ctxa.shop.security-events");
            assertThat(topics.getDlq()).isEqualTo("ctxa.shop.security-events-dlq");
            assertThat(topics.getSoarAction()).isEqualTo("ctxa.shop.soar-action-events");
        }
    }

    @Test
    @DisplayName("without a name of the application a default is ctxa. and the name it had")
    void theDefaultsWithoutAName() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            SecurityKafkaProperties.TopicSettings topics = bound(Map.of());

            assertThat(topics.getDlq()).isEqualTo("ctxa.security-events-dlq");
            assertThat(topics.getThreat()).isEqualTo("ctxa.threat-indicators");
            assertThat(topics.getSoarAction()).isEqualTo("ctxa.soar-action-events");
        }
    }

    @Test
    @DisplayName("a name the operator set is used as it is, a name like the old default included; the others keep their default")
    void aNameTheOperatorSetIsUsedAsItIs() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            SecurityKafkaProperties.TopicSettings topics = bound(Map.of(
                    "contexa.security.kafka.topic.dlq", "security-events-dlq",
                    "contexa.security.kafka.topic.soar-action", "soar-action-events",
                    "contexa.security.kafka.topic.threat", "ops.Threats_1"));

            assertThat(topics.getDlq()).isEqualTo("security-events-dlq");
            assertThat(topics.getSoarAction()).isEqualTo("soar-action-events");
            assertThat(topics.getThreat()).isEqualTo("ops.Threats_1");
            assertThat(topics.getGeneral()).isEqualTo("ctxa.shop.security-events");
        }
    }

    @Test
    @DisplayName("a default follows the name bound when it is read, a name that was set does not")
    void aDefaultIsReadWhenItIsUsed() {
        SecurityKafkaProperties properties = new SecurityKafkaProperties();
        properties.getTopic().setAudit("audit-of-ops");
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("clinic")) {
            assertThat(properties.getTopic().getDlq()).isEqualTo("ctxa.clinic.security-events-dlq");
            assertThat(properties.getTopic().getAudit()).isEqualTo("audit-of-ops");
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            assertThat(properties.getTopic().getDlq()).isEqualTo("ctxa.shop.security-events-dlq");
            assertThat(properties.getTopic().getAudit()).isEqualTo("audit-of-ops");
        }
    }
}
