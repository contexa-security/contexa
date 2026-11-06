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

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.common.errors.TimeoutException;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;
import org.springframework.kafka.KafkaException;
import org.springframework.kafka.core.KafkaTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-79: a publication never holds the thread of the request it is made for. A producer waits up to its limit for a
 * topic it cannot find; that wait, and a send's failure, belong to the publisher's own thread.
 */
@Timeout(value = 20, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class KafkaSecurityEventPublisherHandOffTest {

    private static final Duration AT_ONCE = Duration.ofMillis(500);

    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, Object> template = mock(KafkaTemplate.class);
    private final SecurityKafkaProperties properties = new SecurityKafkaProperties();
    private final CountDownLatch release = new CountDownLatch(1);
    private KafkaSecurityEventPublisher publisher;

    @AfterEach
    void close() {
        release.countDown();
        if (publisher != null) {
            publisher.destroy();
        }
    }

    private void sendsHoldTheirThreadUntilReleased() {
        when(template.send(anyString(), anyString(), any())).thenAnswer(call -> {
            release.await();
            return CompletableFuture.completedFuture(null);
        });
    }

    @Test
    void aSendThatHoldsItsThreadDoesNotHoldTheCaller() {
        sendsHoldTheirThreadUntilReleased();
        publisher = new KafkaSecurityEventPublisher(template, properties);

        Duration took = timed(() -> publisher.publishGenericSecurityEvent(event("session-1")));

        assertThat(took).isLessThan(AT_ONCE);
        release.countDown();
        Awaitility.await().untilAsserted(() ->
                assertThat(publisher.getStatistics()).containsEntry("publish_confirmed_count", 1L));
    }

    /** What KafkaTemplate throws for a topic the producer does not find within its limit. */
    @Test
    void aSendRefusedBeforeItLeftIsCountedAndGoesToTheDeadLetterTopic() {
        when(template.send(anyString(), anyString(), any())).thenThrow(new KafkaException("Send failed",
                new TimeoutException("Topic security.events.authentication.success not present in metadata after 3000 ms")));
        when(template.send(anyString(), any())).thenReturn(CompletableFuture.completedFuture(null));
        publisher = new KafkaSecurityEventPublisher(template, properties);

        publisher.publishGenericSecurityEvent(event("session-1"));

        Awaitility.await().untilAsserted(() -> assertThat(publisher.getStatistics())
                .containsEntry("publish_failed_count", 1L)
                .containsEntry("dlq_dispatch_confirmed_count", 1L));
    }

    @Test
    void aFullQueueNeitherHoldsNorFailsTheCaller() {
        sendsHoldTheirThreadUntilReleased();
        publisher = new KafkaSecurityEventPublisher(template, properties);

        Duration took = timed(() -> {
            for (int call = 0; call < KafkaSecurityEventPublisher.QUEUE_CAPACITY + 10; call++) {
                publisher.publishGenericSecurityEvent(event("session-" + call));
            }
        });

        assertThat(took).isLessThan(Duration.ofSeconds(2));
        assertThat((long) publisher.getStatistics().get("publish_failed_count")).as("those the queue had no room for")
                .isGreaterThanOrEqualTo(9L);
    }

    @Test
    void eventsLeaveInTheOrderTheyCame() {
        List<String> sent = new CopyOnWriteArrayList<>();
        when(template.send(anyString(), anyString(), any())).thenAnswer(call -> {
            sent.add(((ZeroTrustSpringEvent) call.getArgument(2)).getUserId());
            return CompletableFuture.completedFuture(null);
        });
        publisher = new KafkaSecurityEventPublisher(template, properties);

        List<String> users = List.of("user-1", "user-2", "user-3", "user-4", "user-5");
        users.forEach(user -> publisher.publishGenericSecurityEvent(event("session-1", user)));

        Awaitility.await().untilAsserted(() -> assertThat(sent).containsExactlyElementsOf(users));
    }

    @Test
    void anEventIsPublishedOnTheTopicOfItsCategoryAndType() {
        when(template.send(anyString(), anyString(), any())).thenReturn(CompletableFuture.completedFuture(null));
        publisher = new KafkaSecurityEventPublisher(template, properties);

        publisher.publishGenericSecurityEvent(event("session-1"));

        Awaitility.await().untilAsserted(() -> verify(template)
                .send(eq("security.events.authorization.method"), eq("session-1"), any()));
    }

    /** A callback runs on the producer's own thread, which a send that waits for metadata would stop. */
    @Test
    void aFailureReportedByTheProducerSendsTheDeadLetterFromThePublishersThread() {
        CompletableFuture<Object> delivery = new CompletableFuture<>();
        doReturnDelivery(delivery);
        AtomicReference<String> deadLetterThread = new AtomicReference<>();
        when(template.send(anyString(), any())).thenAnswer(call -> {
            deadLetterThread.set(Thread.currentThread().getName());
            return CompletableFuture.completedFuture(null);
        });
        publisher = new KafkaSecurityEventPublisher(template, properties);
        publisher.publishGenericSecurityEvent(event("session-1"));
        Awaitility.await().untilAsserted(() -> verify(template).send(anyString(), anyString(), any()));

        Thread producerThread = new Thread(() -> delivery.completeExceptionally(new TimeoutException("expired")),
                "kafka-producer-network-thread");
        producerThread.start();

        Awaitility.await().untilAsserted(() -> assertThat(deadLetterThread.get()).isEqualTo(KafkaSecurityEventPublisher.SENDER_THREAD));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void doReturnDelivery(CompletableFuture<Object> delivery) {
        when(template.send(anyString(), anyString(), any())).thenReturn((CompletableFuture) delivery);
    }

    /** An event that waited past a send's own limit would be analysed as a moment long gone. */
    @Test
    void anEventThatWaitedLongerThanASendMayTakeIsNotSent() {
        sendsHoldTheirThreadUntilReleased();
        MovableClock clock = new MovableClock();
        publisher = new KafkaSecurityEventPublisher(template, properties, clock);

        publisher.publishGenericSecurityEvent(event("session-first"));
        Awaitility.await().untilAsserted(() -> verify(template).send(anyString(), anyString(), any()));
        publisher.publishGenericSecurityEvent(event("session-stale"));
        clock.instant = clock.instant.plus(KafkaSecurityEventPublisher.MAX_QUEUE_WAIT).plusSeconds(1);
        release.countDown();

        Awaitility.await().untilAsserted(() -> assertThat(publisher.getStatistics())
                .containsEntry("publish_confirmed_count", 1L).containsEntry("publish_failed_count", 1L));
        verify(template, never()).send(anyString(), eq("session-stale"), any());
        verify(template, never()).send(anyString(), any());
    }

    @Test
    void eventsWaitingAtShutdownAreStillSent() {
        when(template.send(anyString(), anyString(), any())).thenReturn(CompletableFuture.completedFuture(null));
        publisher = new KafkaSecurityEventPublisher(template, properties);
        for (int call = 0; call < 20; call++) {
            publisher.publishGenericSecurityEvent(event("session-" + call));
        }

        publisher.destroy();

        ArgumentCaptor<String> keys = ArgumentCaptor.forClass(String.class);
        verify(template, times(20)).send(anyString(), keys.capture(), any());
        assertThat(keys.getAllValues()).hasSize(20).doesNotHaveDuplicates();
    }

    @Test
    void aPublicationAfterShutdownFailsWithoutReachingTheCaller() {
        publisher = new KafkaSecurityEventPublisher(template, properties);
        publisher.destroy();

        publisher.publishGenericSecurityEvent(event("session-1"));

        assertThat(publisher.getStatistics()).containsEntry("publish_failed_count", 1L);
    }

    private static Duration timed(Runnable work) {
        long began = System.nanoTime();
        work.run();
        return Duration.ofNanos(System.nanoTime() - began);
    }

    private static ZeroTrustSpringEvent event(String session) {
        return event(session, "user-1");
    }

    private static ZeroTrustSpringEvent event(String session, String user) {
        return ZeroTrustSpringEvent.builder("evt")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(user)
                .sessionId(session)
                .clientIp("127.0.0.1")
                .payload(Map.of("action", "ALLOW"))
                .build();
    }

    private static final class MovableClock extends Clock {

        volatile Instant instant = Instant.parse("2026-11-05T00:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
