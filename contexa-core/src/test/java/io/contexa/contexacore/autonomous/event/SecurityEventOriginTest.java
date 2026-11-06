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
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.kafka.core.KafkaTemplate;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The name of an application on the Kafka records it publishes, and which records an application reads as its own. */
class SecurityEventOriginTest {

    private static Headers stamped(String name) {
        Headers headers = new RecordHeaders();
        headers.add(SecurityEventOrigin.HEADER, name.getBytes(StandardCharsets.UTF_8));
        return headers;
    }

    @Test
    @DisplayName("an application without a name stamps nothing")
    void withoutANameNothingIsStamped() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(SecurityEventOrigin.headers()).isEmpty();
        }
    }

    @Test
    @DisplayName("an application with a name stamps ctxa-app with its name")
    void withANameTheNameIsStamped() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("Shop")) {
            assertThat(SecurityEventOrigin.HEADER).isEqualTo("ctxa-app");
            assertThat(SecurityEventOrigin.headers()).singleElement().satisfies(header -> {
                assertThat(header.key()).isEqualTo("ctxa-app");
                assertThat(new String(header.value(), StandardCharsets.UTF_8)).isEqualTo("shop");
            });
        }
    }

    @Test
    @DisplayName("a named application reads its own records and no one else's")
    void aNamedApplicationReadsItsOwn() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            assertThat(SecurityEventOrigin.isOwn(stamped("shop"))).isTrue();
            assertThat(SecurityEventOrigin.isOwn(stamped("clinic"))).isFalse();
            assertThat(SecurityEventOrigin.isOwn(stamped("shop-2"))).isFalse();
            assertThat(SecurityEventOrigin.isOwn(stamped("SHOP"))).as("names are compared as they are normalized").isFalse();
            assertThat(SecurityEventOrigin.isOwn(stamped(""))).isFalse();
            assertThat(SecurityEventOrigin.isOwn(new RecordHeaders())).as("a record without a name").isFalse();
            assertThat(SecurityEventOrigin.isOwn(null)).as("a record without headers").isFalse();
        }
    }

    @Test
    @DisplayName("when a record carries the header twice, the last one counts")
    void theLastHeaderCounts() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            Headers headers = stamped("clinic");
            headers.add(SecurityEventOrigin.HEADER, "shop".getBytes(StandardCharsets.UTF_8));

            assertThat(SecurityEventOrigin.isOwn(headers)).isTrue();
        }
    }

    @Test
    @DisplayName("an application without a name reads only the records that carry no name")
    void anUnnamedApplicationReadsOnlyTheNamelessRecords() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(SecurityEventOrigin.isOwn(null)).isTrue();
            assertThat(SecurityEventOrigin.isOwn(new RecordHeaders())).isTrue();
            assertThat(SecurityEventOrigin.isOwn(stamped("shop"))).isFalse();
        }
    }

    @Test
    @DisplayName("the name a record carries is read for the log")
    void theNameInARecord() {
        assertThat(SecurityEventOrigin.nameIn(stamped("shop"))).isEqualTo("shop");
        assertThat(SecurityEventOrigin.nameIn(new RecordHeaders())).isEmpty();
        assertThat(SecurityEventOrigin.nameIn(null)).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("a named application sends a record that carries its name, with the key and the value as they were")
    void aNamedApplicationSendsAStampedRecord() {
        KafkaTemplate<String, Object> template = mock(KafkaTemplate.class);
        when(template.send(any(ProducerRecord.class))).thenReturn(new CompletableFuture<>());

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            SecurityEventOrigin.send(template, "security.events.authorization.method", "session-1", "event");
        }

        ArgumentCaptor<ProducerRecord<String, Object>> sent = ArgumentCaptor.forClass(ProducerRecord.class);
        verify(template).send(sent.capture());
        assertThat(sent.getValue().topic()).isEqualTo("security.events.authorization.method");
        assertThat(sent.getValue().key()).isEqualTo("session-1");
        assertThat(sent.getValue().value()).isEqualTo("event");
        Header header = sent.getValue().headers().lastHeader("ctxa-app");
        assertThat(new String(header.value(), StandardCharsets.UTF_8)).isEqualTo("shop");
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("an application without a name sends through the template as it always did, with no header")
    void anUnnamedApplicationSendsAsItAlwaysDid() {
        KafkaTemplate<String, Object> template = mock(KafkaTemplate.class);
        when(template.send("topic", "key", "event")).thenReturn(new CompletableFuture<>());
        when(template.send("topic", "dead-letter")).thenReturn(new CompletableFuture<>());

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(SecurityEventOrigin.send(template, "topic", "key", "event")).isNotNull();
            assertThat(SecurityEventOrigin.send(template, "topic", null, "dead-letter")).isNotNull();
        }

        verify(template).send("topic", "key", "event");
        verify(template).send("topic", "dead-letter");
    }
}
