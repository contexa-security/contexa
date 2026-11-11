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
package io.contexa.contexacommon.store;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What names Contexa's Kafka topics: {@code ctxa.<name>.} before the name the topic always had, and {@code ctxa.} without
 * a name of the application, so that no topic of Contexa has a name another application on the cluster may use, and two
 * applications with different names never share one.
 */
class ApplicationNamespaceTopicTest {

    /** The longest name Kafka accepts for a topic. */
    private static final int KAFKA_TOPIC_LIMIT = 249;

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t\n"})
    @DisplayName("without a name a topic is ctxa. and the name it had, and the keys and the group stay as they were")
    void withoutAName(String name) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(name)) {
            assertThat(ApplicationNamespace.topic("security-events-dlq")).isEqualTo("ctxa.security-events-dlq");
            assertThat(ApplicationNamespace.topic("security.events.authorization.method"))
                    .isEqualTo("ctxa.security.events.authorization.method");
            assertThat(ApplicationNamespace.topicIdentifier(name)).isEmpty();
            assertThat(ApplicationNamespace.key("security:blocked:users:alice")).isEqualTo("security:blocked:users:alice");
            assertThat(ApplicationNamespace.consumerGroup("security-plane-consumer")).isEqualTo("security-plane-consumer");
        }
    }

    @Test
    @DisplayName("a name puts ctxa.<name>. before the topic, and another name gives other topics")
    void withAName() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("petclinic-a")) {
            assertThat(ApplicationNamespace.topic("security-events-dlq")).isEqualTo("ctxa.petclinic-a.security-events-dlq");
            assertThat(ApplicationNamespace.topic("network-events")).isEqualTo("ctxa.petclinic-a.network-events");
            assertThat(ApplicationNamespace.topic("security.events.authentication.success"))
                    .isEqualTo("ctxa.petclinic-a.security.events.authentication.success");
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("petclinic-b")) {
            assertThat(ApplicationNamespace.topic("security-events-dlq")).isEqualTo("ctxa.petclinic-b.security-events-dlq");
        }
    }

    @Test
    @DisplayName("the servers of one application name the same topics, however the name is cased or padded")
    void theServersOfOneApplicationShareTheTopics() {
        String first;
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("Shop")) {
            first = ApplicationNamespace.topic("security-events-dlq");
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("  shop ")) {
            assertThat(ApplicationNamespace.topic("security-events-dlq")).isEqualTo(first).isEqualTo("ctxa.shop.security-events-dlq");
        }
    }

    @Test
    @DisplayName("what a topic cannot hold, a dot and an underscore included, is written as _ and the two hex digits of each byte")
    void escapes() {
        assertThat(ApplicationNamespace.topicIdentifier("order-service")).isEqualTo("order-service");
        assertThat(ApplicationNamespace.topicIdentifier("PetClinic2")).isEqualTo("petclinic2");
        assertThat(ApplicationNamespace.topicIdentifier("my_app")).isEqualTo("my_5fapp");
        assertThat(ApplicationNamespace.topicIdentifier("com.example.app")).isEqualTo("com_2eexample_2eapp");
        assertThat(ApplicationNamespace.topicIdentifier("my app")).isEqualTo("my_20app");
        assertThat(ApplicationNamespace.topicIdentifier("a:b")).isEqualTo("a_3ab");
        assertThat(ApplicationNamespace.topicIdentifier("a~b")).isEqualTo("a_7eb");
        assertThat(ApplicationNamespace.topicIdentifier("한")).isEqualTo("_ed_95_9c");
    }

    @Test
    @DisplayName("the key and the group keep their form: only the topic writes the name in a topic's characters")
    void theKeyAndTheGroupKeepTheirForm() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("My_App.v2")) {
            assertThat(ApplicationNamespace.identifier()).isEqualTo("my_app.v2");
            assertThat(ApplicationNamespace.key("security:blocked:users:alice"))
                    .isEqualTo("ctxa:my_app.v2:security:blocked:users:alice");
            assertThat(ApplicationNamespace.consumerGroup("security-plane-consumer"))
                    .isEqualTo("security-plane-consumer.my_app.v2");
            assertThat(ApplicationNamespace.topic("security-events-dlq")).isEqualTo("ctxa.my_5fapp_2ev2.security-events-dlq");
        }
    }

    @Test
    @DisplayName("names that differ give topics that differ, also as Kafka compares them, and the name in a topic holds no dot")
    void differentNamesStayDifferent() {
        String[] names = {"", "a", "a-b", "a.b", "a_b", "a_2eb", "a_5fb", "a2eb", "a5fb", "a.2eb", "a~2eb", "a~b", "a b",
                "a:b", "a*b", "my.app", "my_app", "my-app", "myapp", "MyApp", "한글", "é", "e", "app", "app1", "app-1",
                "ctxa", "ctxa.a", "security", "security.events", "security-events", "x.security.events"};
        Map<String, String> folded = new HashMap<>();
        Map<String, String> exact = new HashMap<>();
        for (String name : names) {
            String identifier = ApplicationNamespace.topicIdentifier(name);
            assertThat(identifier).matches("[a-z0-9_-]*");
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(name)) {
                String prefix = ApplicationNamespace.topic("");
                assertThat(prefix).as("the name of %s in a topic", name)
                        .isEqualTo(identifier.isEmpty() ? "ctxa." : "ctxa." + identifier + ".");
                String topic = ApplicationNamespace.topic("security-events-dlq");
                assertThat(topic).matches("[a-zA-Z0-9._-]+");
                String sameNameOf = exact.put(topic, name);
                if (sameNameOf != null && !ApplicationNamespace.normalize(sameNameOf).equals(ApplicationNamespace.normalize(name))) {
                    throw new AssertionError(name + " and " + sameNameOf + " name the same topic " + topic);
                }
                // Kafka refuses a topic whose name differs from another's only by '.' against '_'.
                String collidesWith = folded.put(topic.replace('.', '_'), name);
                if (collidesWith != null
                        && !ApplicationNamespace.normalize(collidesWith).equals(ApplicationNamespace.normalize(name))) {
                    throw new AssertionError(name + " and " + collidesWith + " name topics Kafka takes for one: " + topic);
                }
            }
        }
    }

    @Test
    @DisplayName("a long name is cut as for a key, ends in a digest of the whole, and its topics stay within Kafka's limit")
    void longNames() {
        String common = "an.application_name-that-is-much-longer-than-the-limit-of-the-identifier";
        String first = ApplicationNamespace.topicIdentifier(common + "-one");
        String second = ApplicationNamespace.topicIdentifier(common + "-two");

        assertThat(first).hasSize(ApplicationNamespace.MAX_IDENTIFIER_LENGTH).matches("[a-z0-9_-]+");
        assertThat(second).hasSize(ApplicationNamespace.MAX_IDENTIFIER_LENGTH).matches("[a-z0-9_-]+");
        assertThat(first).isNotEqualTo(second).isEqualTo(ApplicationNamespace.topicIdentifier(common + "-one"));
        assertThat(ApplicationNamespace.topicIdentifier("한".repeat(40))).hasSize(ApplicationNamespace.MAX_IDENTIFIER_LENGTH);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("한".repeat(400))) {
            assertThat(ApplicationNamespace.topic("security.events.authentication.success").length())
                    .isLessThanOrEqualTo(KAFKA_TOPIC_LIMIT);
            assertThat(ApplicationNamespace.topic("security-authorization-events").length())
                    .isLessThanOrEqualTo(KAFKA_TOPIC_LIMIT);
        }
    }
}
