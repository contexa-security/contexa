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
package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.common.internals.Topic;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * PR-73: the topics made at start are the ones the publisher writes to and the collector reads. They are the
 * application's own: the collector of one application never reads the topics of another, nor a topic that is not
 * Contexa's.
 */
class SecurityEventTopicsTest {

    /** Names of applications, some of them chosen to look like the topics of others. */
    private static final List<String> APPLICATIONS = List.of("", "shop", "clinic", "shop-2", "shop.events", "shop_events",
            "security", "security.events", "x.security.events", "ctxa", "a", "a.b", "a_b", "한글");

    @Test
    void theNameIsTheCategoryAndTheTypeInLowerCaseInTheApplicationsNamespace() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            assertThat(SecurityEventTopics.of(ZeroTrustEventCategory.AUTHENTICATION, "SUCCESS"))
                    .isEqualTo("ctxa.shop.security.events.authentication.success");
            assertThat(SecurityEventTopics.of(ZeroTrustEventCategory.CUSTOM, "Order-Placed"))
                    .isEqualTo("ctxa.shop.security.events.custom.order-placed");
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(SecurityEventTopics.of(ZeroTrustEventCategory.AUTHORIZATION, "METHOD"))
                    .isEqualTo("ctxa.security.events.authorization.method");
        }
    }

    @Test
    void everyTypeTheEventDeclaresHasItsTopicMadeAtStart() throws Exception {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            List<String> declared = new ArrayList<>();
            for (Field field : ZeroTrustSpringEvent.class.getFields()) {
                if (Modifier.isStatic(field.getModifiers()) && field.getName().startsWith("TYPE_")) {
                    String[] name = field.getName().split("_");
                    declared.add(SecurityEventTopics.of(ZeroTrustEventCategory.valueOf(name[1].toUpperCase(Locale.ROOT)),
                            (String) field.get(null)));
                }
            }

            assertThat(declared).isNotEmpty();
            assertThat(SecurityEventTopics.declared()).containsExactlyInAnyOrderElementsOf(declared)
                    .allMatch(topic -> topic.startsWith("ctxa.shop.security.events."));
        }
    }

    @Test
    void theCollectorsPatternReadsTheTopicsOfItsApplicationAndNoOther() {
        String clinic;
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("clinic")) {
            clinic = SecurityEventTopics.of(ZeroTrustEventCategory.AUTHORIZATION, "METHOD");
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            Pattern pattern = Pattern.compile(SecurityEventTopics.pattern());

            assertThat(SecurityEventTopics.declared()).allMatch(topic -> pattern.matcher(topic).matches());
            assertThat(pattern.matcher(SecurityEventTopics.of(ZeroTrustEventCategory.CUSTOM, "SOMETHING_ELSE")).matches())
                    .isTrue();
            assertThat(pattern.matcher(clinic).matches()).as("another application's topic").isFalse();
            assertThat(pattern.matcher("security.events.authorization.method").matches())
                    .as("a topic outside Contexa's namespace, as an application that is not Contexa may have").isFalse();
            assertThat(pattern.matcher("ctxa.security.events.authorization.method").matches())
                    .as("the topic of a Contexa without a name").isFalse();
            assertThat(pattern.matcher("ctxa.shop.security-events").matches()).as("the general topic is another topic").isFalse();
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            Pattern pattern = Pattern.compile(SecurityEventTopics.pattern());

            assertThat(pattern.matcher("ctxa.security.events.authorization.method").matches()).isTrue();
            assertThat(pattern.matcher("security.events.orders.created").matches())
                    .as("the topic of an application that is not Contexa").isFalse();
            assertThat(pattern.matcher(clinic).matches()).as("the topic of a Contexa with a name").isFalse();
        }
    }

    @Test
    void thePatternOfOneApplicationReachesNoTopicOfAnotherAndKafkaTellsTheirTopicsApart() {
        for (String reader : APPLICATIONS) {
            Pattern pattern;
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(reader)) {
                pattern = Pattern.compile(SecurityEventTopics.pattern());
            }
            List<String> own = topicsOf(reader);
            for (String writer : APPLICATIONS) {
                if (writer.equals(reader)) {
                    continue;
                }
                for (String topic : topicsOf(writer)) {
                    assertThat(pattern.matcher(topic).matches()).as("%s reads %s of %s", reader, topic, writer).isFalse();
                    for (String mine : own) {
                        assertThat(Topic.hasCollision(mine, topic)).as("%s of %s and %s of %s", mine, reader, topic, writer)
                                .isFalse();
                    }
                }
            }
        }
    }

    @Test
    void everyTopicIsOneKafkaAccepts() {
        for (String application : List.of("", "shop", "My App.v2", "x".repeat(400), "한".repeat(400))) {
            for (String topic : topicsOf(application)) {
                assertThatCode(() -> Topic.validate(topic)).as("%s of %s", topic, application).doesNotThrowAnyException();
            }
        }
    }

    /** The topics an application writes to: its event topics, one of its own types, and the dead letters. */
    private static List<String> topicsOf(String application) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(application)) {
            List<String> topics = new ArrayList<>(SecurityEventTopics.declared());
            topics.add(SecurityEventTopics.of(ZeroTrustEventCategory.CUSTOM, "order.placed"));
            topics.add(new SecurityKafkaProperties().getTopic().getDlq());
            return topics;
        }
    }
}
