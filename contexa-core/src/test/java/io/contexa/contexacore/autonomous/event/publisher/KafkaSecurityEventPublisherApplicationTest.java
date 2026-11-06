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
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.Header;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.kafka.KafkaException;
import org.springframework.kafka.core.KafkaTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** An application with a name stamps every record it publishes with the name; one without a name stamps none. */
class KafkaSecurityEventPublisherApplicationTest {

    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, Object> template = mock(KafkaTemplate.class);
    private final SecurityKafkaProperties properties = new SecurityKafkaProperties();
    private KafkaSecurityEventPublisher publisher;

    @AfterEach
    void close() {
        if (publisher != null) {
            publisher.destroy();
        }
    }

    private static ZeroTrustSpringEvent event() {
        return ZeroTrustSpringEvent.builder("event").category(ZeroTrustEventCategory.AUTHORIZATION).eventType("METHOD")
                .userId("alice").sessionId("session-1").clientIp("10.0.0.1").payload(Map.of("action", "ALLOW")).build();
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("an event of a named application leaves on its topic, with its key and the name of the application")
    void aNamedApplicationStampsItsEvents() {
        when(template.send(any(ProducerRecord.class))).thenReturn(CompletableFuture.completedFuture(null));

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            publisher = new KafkaSecurityEventPublisher(template, properties);
            publisher.publishGenericSecurityEvent(event());

            ArgumentCaptor<ProducerRecord<String, Object>> sent = ArgumentCaptor.forClass(ProducerRecord.class);
            Awaitility.await().untilAsserted(() -> verify(template).send(sent.capture()));
            assertThat(sent.getValue().topic()).isEqualTo("security.events.authorization.method");
            assertThat(sent.getValue().key()).isEqualTo("session-1");
            Header header = sent.getValue().headers().lastHeader("ctxa-app");
            assertThat(new String(header.value(), StandardCharsets.UTF_8)).isEqualTo("shop");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("the dead letter of a named application carries the name too")
    void aDeadLetterIsStamped() {
        when(template.send(any(ProducerRecord.class)))
                .thenThrow(new KafkaException("Send failed"))
                .thenReturn(CompletableFuture.completedFuture(null));

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            publisher = new KafkaSecurityEventPublisher(template, properties);
            publisher.publishGenericSecurityEvent(event());

            ArgumentCaptor<ProducerRecord<String, Object>> sent = ArgumentCaptor.forClass(ProducerRecord.class);
            Awaitility.await().untilAsserted(() -> verify(template, org.mockito.Mockito.times(2)).send(sent.capture()));
            ProducerRecord<String, Object> deadLetter = sent.getAllValues().get(1);
            assertThat(deadLetter.topic()).isEqualTo(properties.getTopic().getDlq());
            assertThat(new String(deadLetter.headers().lastHeader("ctxa-app").value(), StandardCharsets.UTF_8))
                    .isEqualTo("shop");
        }
    }

    @Test
    @DisplayName("an application without a name publishes as it always did: the template is called with the topic, the key and the event")
    void anUnnamedApplicationStampsNothing() {
        when(template.send(anyString(), anyString(), any())).thenReturn(CompletableFuture.completedFuture(null));

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            publisher = new KafkaSecurityEventPublisher(template, properties);
            publisher.publishGenericSecurityEvent(event());

            Awaitility.await().untilAsserted(() -> verify(template, atLeastOnce())
                    .send(org.mockito.ArgumentMatchers.eq("security.events.authorization.method"),
                            org.mockito.ArgumentMatchers.eq("session-1"), any()));
            verify(template, never()).send(any(ProducerRecord.class));
        }
    }
}
