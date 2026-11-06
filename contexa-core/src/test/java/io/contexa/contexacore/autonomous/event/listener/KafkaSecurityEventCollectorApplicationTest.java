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
package io.contexa.contexacore.autonomous.event.listener;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.SecurityEventOrigin;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Two applications on one Kafka cluster each read every record of the shared topics, and each analyses only its own: the
 * record of another application is skipped, and its offset moves on.
 */
class KafkaSecurityEventCollectorApplicationTest {

    private static final String TOPIC = "security.events.authorization.method";

    private final ObjectMapper reader = mock(ObjectMapper.class);
    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, Object> template = mock(KafkaTemplate.class);
    private final Acknowledgment acknowledgment = mock(Acknowledgment.class);
    private final List<SecurityEvent> received = new ArrayList<>();
    private final KafkaSecurityEventCollector collector =
            new KafkaSecurityEventCollector(reader, template, new SecurityKafkaProperties());
    private ApplicationNamespace.Scope scope;

    private final SecurityEventListener analysis = new SecurityEventListener() {
        @Override
        public void onSecurityEvent(SecurityEvent event) {
            received.add(event);
        }
    };

    private final SecurityEventListener slowAnalysis = new SecurityEventListener() {
        @Override
        public void onSecurityEvent(SecurityEvent event) {
            received.add(event);
        }

        @Override
        public boolean settlesItsEvents() {
            return true;
        }
    };

    @BeforeEach
    void setUp() throws Exception {
        scope = ApplicationNamespace.using("shop");
        when(reader.readValue(eq("{json}"), eq(ZeroTrustSpringEvent.class))).thenReturn(
                ZeroTrustSpringEvent.builder("event").category(ZeroTrustEventCategory.AUTHORIZATION).eventType("METHOD")
                        .userId("alice").sessionId("session-1").clientIp("10.0.0.1").payload(Map.of("action", "ALLOW")).build());
    }

    @AfterEach
    void restore() {
        scope.close();
    }

    /** The record as the consumer hands it over: with the name of an application, or without one when it is {@code null}. */
    private static ConsumerRecord<String, String> record(long offset, String application) {
        ConsumerRecord<String, String> record = new ConsumerRecord<>(TOPIC, 0, offset, "key", "{json}");
        if (application != null) {
            record.headers().add(SecurityEventOrigin.HEADER, application.getBytes(StandardCharsets.UTF_8));
        }
        return record;
    }

    private void consume(long offset, String application) {
        collector.consumeZeroTrustEvents("{json}", TOPIC, 0, offset, record(offset, application), acknowledgment);
    }

    @Test
    @DisplayName("a record that carries the name of the application is analysed")
    void itsOwnRecordIsAnalysed() {
        collector.registerListener(analysis);

        consume(1, "shop");
        consume(2, "shop");

        assertThat(received).hasSize(2);
        assertThat(collector.getStatistics()).containsEntry("other_application_events_skipped", 0L);
    }

    @Test
    @DisplayName("a record of another application is not analysed, and its offset is acknowledged all the same")
    void aRecordOfAnotherApplicationIsSkippedAndAcknowledged() {
        collector.registerListener(analysis);

        consume(1, "clinic");

        assertThat(received).isEmpty();
        verify(acknowledgment).acknowledge();
        assertThat(collector.getStatistics()).containsEntry("other_application_events_skipped", 1L);
    }

    @Test
    @DisplayName("a record without a name belongs to no named application: it is skipped and acknowledged")
    void aRecordWithoutANameIsNotANamedApplicationsRecord() {
        collector.registerListener(analysis);

        consume(1, null);

        assertThat(received).isEmpty();
        verify(acknowledgment).acknowledge();
    }

    @Test
    @DisplayName("an application without a name analyses the records without one and skips those that carry a name")
    void anApplicationWithoutANameTakesOnlyTheRecordsWithoutOne() {
        collector.registerListener(analysis);

        try (ApplicationNamespace.Scope unnamed = ApplicationNamespace.using("")) {
            consume(1, null);
            consume(2, "shop");
        }

        assertThat(received).hasSize(1);
        assertThat(collector.getStatistics()).containsEntry("other_application_events_skipped", 1L);
        verify(acknowledgment, times(2)).acknowledge();
    }

    @Test
    @DisplayName("a skipped record commits behind the record of its own that is still being analysed, not before it")
    void aSkippedRecordDoesNotCommitPastAnUndecidedOne() {
        DecidedRecordAcknowledger decided = new DecidedRecordAcknowledger(Duration.ofMinutes(13));
        collector.setDecidedRecordAcknowledger(decided);
        collector.registerListener(slowAnalysis);
        Acknowledgment ownRecord = mock(Acknowledgment.class);
        Acknowledgment skippedRecord = mock(Acknowledgment.class);

        collector.consumeZeroTrustEvents("{json}", TOPIC, 0, 10, record(10, "shop"), ownRecord);
        collector.consumeZeroTrustEvents("{json}", TOPIC, 0, 11, record(11, "clinic"), skippedRecord);

        verify(ownRecord, never()).acknowledge();
        verify(skippedRecord, never()).acknowledge();
        assertThat(decided.undecidedRecords()).isEqualTo(1);

        collector.settled(received.get(0));

        verify(skippedRecord).acknowledge();
    }

    @Test
    @DisplayName("a partition of other applications' records alone commits at once, so that it never holds the consumer back")
    void aRunOfSkippedRecordsCommits() {
        DecidedRecordAcknowledger decided = new DecidedRecordAcknowledger(Duration.ofMinutes(13));
        collector.setDecidedRecordAcknowledger(decided);
        Acknowledgment first = mock(Acknowledgment.class);
        Acknowledgment second = mock(Acknowledgment.class);

        collector.consumeZeroTrustEvents("{json}", TOPIC, 0, 1, record(1, "clinic"), first);
        collector.consumeZeroTrustEvents("{json}", TOPIC, 0, 2, record(2, "clinic"), second);

        verify(first).acknowledge();
        verify(second).acknowledge();
        assertThat(decided.undecidedRecords()).isZero();
    }

    @Test
    @DisplayName("the five-argument form is a record that carries no name")
    void theShortFormCarriesNoName() {
        collector.registerListener(analysis);

        collector.consumeZeroTrustEvents("{json}", TOPIC, 0, 5, acknowledgment);

        assertThat(received).isEmpty();
        assertThat(SecurityEventOrigin.isOwn(null)).isFalse();
    }
}
