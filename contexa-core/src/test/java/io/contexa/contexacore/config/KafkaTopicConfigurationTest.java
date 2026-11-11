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
package io.contexa.contexacore.config;

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.event.SecurityEventTopics;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.admin.NewTopic;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The topics Contexa makes at start are the ones something writes to or reads: the topic of every declared event, which
 * the publisher writes and the collector reads, and the dead letters, which both write. A topic that nothing writes to
 * and nothing reads stays off a cluster the application shares with others.
 */
class KafkaTopicConfigurationTest {

    private static SecurityKafkaProperties.TopicSettings bound(Map<String, String> configuration) {
        return new Binder(new MapConfigurationPropertySource(configuration))
                .bind("contexa.security.kafka", SecurityKafkaProperties.class)
                .orElseGet(SecurityKafkaProperties::new).getTopic();
    }

    private static List<String> names(List<NewTopic> topics) {
        return topics.stream().map(NewTopic::name).toList();
    }

    @Test
    @DisplayName("only the declared event topics and the dead letters are made, in the namespace of the application")
    void onlyWhatIsUsedIsMade() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            List<NewTopic> made = new KafkaTopicConfiguration().topicsToMake(bound(Map.of()));

            assertThat(names(made)).containsExactlyInAnyOrder(
                    "ctxa.shop.security.events.authentication.success",
                    "ctxa.shop.security.events.authentication.mfa",
                    "ctxa.shop.security.events.authorization.method",
                    "ctxa.shop.security-events-dlq");
        }
    }

    @Test
    @DisplayName("without a name of the application the same topics are made under ctxa.")
    void withoutANameOfTheApplication() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            List<NewTopic> made = new KafkaTopicConfiguration().topicsToMake(bound(Map.of()));

            assertThat(names(made)).containsExactlyInAnyOrder(
                    "ctxa.security.events.authentication.success",
                    "ctxa.security.events.authentication.mfa",
                    "ctxa.security.events.authorization.method",
                    "ctxa.security-events-dlq");
        }
    }

    @Test
    @DisplayName("every topic made is read by the collector's subscription or is the dead letters the publisher and the collector write")
    void everyTopicMadeIsUsed() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            SecurityKafkaProperties.TopicSettings settings = bound(Map.of());
            Pattern collected = Pattern.compile(SecurityEventTopics.pattern());

            for (String topic : names(new KafkaTopicConfiguration().topicsToMake(settings))) {
                assertThat(collected.matcher(topic).matches() || topic.equals(settings.getDlq()))
                        .as("%s is read or written", topic).isTrue();
            }
            assertThat(names(new KafkaTopicConfiguration().topicsToMake(settings))).containsAll(SecurityEventTopics.declared());
        }
    }

    @Test
    @DisplayName("a dead letter name the operator set is made as it is set, and a name set for a topic nothing uses makes no topic")
    void anOperatorsNamesChangeOnlyWhatIsUsed() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            SecurityKafkaProperties.TopicSettings settings = bound(Map.of(
                    "contexa.security.kafka.topic.dlq", "ops.dead-letters",
                    "contexa.security.kafka.topic.authorization", "ops.authorization",
                    "contexa.security.kafka.topic.authentication", "ops.authentication",
                    "contexa.security.kafka.topic.incident", "ops.incident",
                    "contexa.security.kafka.topic.threat", "ops.threat",
                    "contexa.security.kafka.topic.audit", "ops.audit",
                    "contexa.security.kafka.topic.general", "ops.general",
                    "contexa.security.kafka.topic.soar-action", "ops.soar"));

            assertThat(names(new KafkaTopicConfiguration().topicsToMake(settings))).containsExactlyInAnyOrder(
                    "ctxa.shop.security.events.authentication.success",
                    "ctxa.shop.security.events.authentication.mfa",
                    "ctxa.shop.security.events.authorization.method",
                    "ops.dead-letters");
        }
    }

    @Test
    @DisplayName("the topics that are made keep the partitions and the retention they were made with")
    void theKeptTopicsKeepTheirSettings() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            for (NewTopic topic : new KafkaTopicConfiguration().topicsToMake(bound(Map.of()))) {
                if (topic.name().equals("ctxa.shop.security-events-dlq")) {
                    assertThat(topic.numPartitions()).isEqualTo(1);
                    assertThat(topic.replicationFactor()).isEqualTo((short) 1);
                    assertThat(topic.configs()).containsEntry("retention.ms", "2592000000");
                } else {
                    assertThat(topic.numPartitions()).as(topic.name()).isEqualTo(3);
                    assertThat(topic.configs()).as(topic.name()).containsEntry("retention.ms", "604800000");
                }
            }
        }
    }
}
