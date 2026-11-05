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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** A record is acknowledged when the analysis is done with it, not when it is taken in. */
class KafkaSecurityEventCollectorDecidedRecordTest {

    private static final String TOPIC = "security.events.authorization.method";

    private final ObjectMapper reader = mock(ObjectMapper.class);
    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, Object> template = mock(KafkaTemplate.class);
    private final Acknowledgment acknowledgment = mock(Acknowledgment.class);
    private final DecidedRecordAcknowledger decided = new DecidedRecordAcknowledger(Duration.ofMinutes(13));
    private final List<SecurityEvent> received = new ArrayList<>();
    private final KafkaSecurityEventCollector collector =
            new KafkaSecurityEventCollector(reader, template, new SecurityKafkaProperties());

    /** The analysis: it goes on after the event is handed over and says when it is done. */
    private final SecurityEventListener analysis = new SecurityEventListener() {
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
        collector.setDecidedRecordAcknowledger(decided);
        when(reader.readValue(eq("{json}"), eq(ZeroTrustSpringEvent.class))).thenReturn(event(Map.of("action", "ALLOW")));
    }

    private static ZeroTrustSpringEvent event(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder("event").category(ZeroTrustEventCategory.AUTHORIZATION).eventType("METHOD")
                .userId("alice").sessionId("session-1").clientIp("10.0.0.1").payload(payload).build();
    }

    private void consume(long offset, Acknowledgment acknowledgment) {
        collector.consumeZeroTrustEvents("{json}", TOPIC, 0, offset, acknowledgment);
    }

    @Test
    void aRecordGoingToTheAnalysisIsNotAcknowledgedWhenItIsTakenIn() {
        collector.registerListener(analysis);

        consume(10, acknowledgment);

        verify(acknowledgment, never()).acknowledge();
        assertThat(decided.undecidedRecords()).isEqualTo(1);
    }

    @Test
    void itIsAcknowledgedWhenTheAnalysisIsDoneWithIt() {
        collector.registerListener(analysis);
        consume(10, acknowledgment);

        collector.settled(received.get(0));

        verify(acknowledgment).acknowledge();
        assertThat(collector.getStatistics()).containsEntry("ack_count", 1L);
    }

    @Test
    void anEventDoneBeforeTheHandOverReturnsIsNotMissed() {
        collector.registerListener(new SecurityEventListener() {
            @Override
            public void onSecurityEvent(SecurityEvent event) {
                collector.settled(event);
            }

            @Override
            public boolean settlesItsEvents() {
                return true;
            }
        });

        consume(10, acknowledgment);

        verify(acknowledgment).acknowledge();
    }

    @Test
    void theStatisticsTellWhatIsHeldAndWhatWasPassed() {
        collector.registerListener(analysis);

        consume(10, acknowledgment);

        assertThat(collector.getStatistics()).containsEntry("undecided_records", 1L)
                .containsEntry("commit_passed_undecided_count", 0L);
    }

    @Test
    void aListenerThatIsDoneWhenItReturnsLeavesNothingToWaitFor() {
        SecurityEventListener done = mock(SecurityEventListener.class);
        when(done.isActive()).thenReturn(true);
        collector.registerListener(done);

        consume(10, acknowledgment);

        verify(done).onSecurityEvent(any());
        verify(acknowledgment).acknowledge();
    }

    @Test
    void noListenerLeavesNothingToWaitFor() {
        consume(10, acknowledgment);

        verify(acknowledgment).acknowledge();
    }

    @Test
    void anAnalysisThatIsNotActiveLeavesNothingToWaitFor() {
        SecurityEventListener idle = mock(SecurityEventListener.class);
        when(idle.isActive()).thenReturn(false);
        when(idle.settlesItsEvents()).thenReturn(true);
        collector.registerListener(idle);

        consume(10, acknowledgment);

        verify(acknowledgment).acknowledge();
    }

    @Test
    void anEventTheAnalysisWasNotHandedStaysToBeDeliveredAgain() {
        SecurityEventListener failing = mock(SecurityEventListener.class);
        when(failing.isActive()).thenReturn(true);
        when(failing.getListenerName()).thenReturn("failing");
        when(failing.settlesItsEvents()).thenReturn(true);
        doThrow(new IllegalStateException("interrupted")).when(failing).onSecurityEvent(any());
        collector.registerListener(failing);
        doReturn(CompletableFuture.completedFuture(null)).when(template).send(anyString(), any());

        assertThatThrownBy(() -> consume(10, acknowledgment)).isInstanceOf(IllegalStateException.class);

        verify(acknowledgment, never()).acknowledge();
    }

    @Test
    void aRecordThatCannotBeReadHoldsNothingBack() throws Exception {
        collector.registerListener(analysis);
        when(reader.readValue(eq("{broken}"), eq(ZeroTrustSpringEvent.class)))
                .thenThrow(new JsonParseException(null, "not an event"));
        doReturn(CompletableFuture.completedFuture(null)).when(template).send(anyString(), any());
        Acknowledgment next = mock(Acknowledgment.class);

        assertThatThrownBy(() -> collector.consumeZeroTrustEvents("{broken}", TOPIC, 0, 10, acknowledgment))
                .isInstanceOf(IllegalStateException.class);
        consume(11, next);
        collector.settled(received.get(0));

        assertThat(decided.undecidedRecords()).isZero();
        verify(next).acknowledge();
    }

    @Test
    void withoutTheAcknowledgerARecordIsAcknowledgedWhenItIsTakenIn() {
        collector.setDecidedRecordAcknowledger(null);
        collector.registerListener(analysis);

        consume(10, acknowledgment);

        verify(acknowledgment).acknowledge();
    }

    @Test
    void anEventOfNoRecordSettlesNothing() {
        collector.registerListener(analysis);
        consume(10, acknowledgment);

        collector.settled(SecurityEvent.builder().eventId("not-a-record").build());
        collector.settled(null);

        verify(acknowledgment, never()).acknowledge();
    }

    /** An event's payload becomes its metadata: what it says of a record is not what the record is. */
    @Test
    void anEventCannotSpeakForAnotherRecord() throws Exception {
        collector.registerListener(analysis);
        when(reader.readValue(eq("{forged}"), eq(ZeroTrustSpringEvent.class))).thenReturn(event(
                Map.of("kafka.topic", TOPIC, "kafka.partition", "0", "kafka.offset", "10")));
        consume(10, acknowledgment);
        Acknowledgment forged = mock(Acknowledgment.class);

        collector.consumeZeroTrustEvents("{forged}", TOPIC, 0, 11, forged);
        collector.settled(received.get(1));

        verify(acknowledgment, never()).acknowledge();
    }

    /** Analysed where it was published, the event is no record of this consumer, whatever its payload says. */
    @Test
    void anEventKafkaDidNotTakeSettlesNoRecord() {
        collector.registerListener(analysis);
        consume(10, acknowledgment);

        collector.analyseHere(event(Map.of("kafka.topic", TOPIC, "kafka.partition", "0", "kafka.offset", "10")));
        collector.settled(received.get(1));

        verify(acknowledgment, never()).acknowledge();
    }

    @Test
    void aRecordOfAStoppedCollectorIsNeitherTakenNorAcknowledged() {
        collector.registerListener(analysis);
        collector.shutdown();

        consume(10, acknowledgment);

        assertThat(decided.undecidedRecords()).isZero();
        verify(acknowledgment, never()).acknowledge();
    }
}
