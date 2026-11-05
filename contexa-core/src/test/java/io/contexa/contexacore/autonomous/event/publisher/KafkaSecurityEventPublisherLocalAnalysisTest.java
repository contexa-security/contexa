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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.apache.kafka.common.errors.TimeoutException;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;
import org.springframework.kafka.KafkaException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Q-26 (PR-79): an event Kafka did not take is analysed on the node that had it, as standalone analyses it, so a topic
 * that cannot be used costs no decision. The event keeps one id on both ways, so one that reached the broker after all
 * is not analysed twice.
 */
@Timeout(value = 20, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class KafkaSecurityEventPublisherLocalAnalysisTest {

    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, Object> template = mock(KafkaTemplate.class);
    private final SecurityKafkaProperties properties = new SecurityKafkaProperties();
    private final List<ZeroTrustSpringEvent> analysedHere = new CopyOnWriteArrayList<>();
    private KafkaSecurityEventPublisher publisher;

    @AfterEach
    void close() {
        if (publisher != null) {
            publisher.destroy();
        }
    }

    private static ZeroTrustSpringEvent event(String session) {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS).userId("alice").sessionId(session)
                .clientIp("10.0.0.1").userAgent("client").resource("/login").payload(Map.of("authMethod", "form"))
                .build();
    }

    private void aTopicThatCannotBeUsed() {
        when(template.send(anyString(), anyString(), any())).thenThrow(new KafkaException("Send failed",
                new TimeoutException("Topic security.events.authentication.success not present in metadata after 3000 ms")));
        when(template.send(anyString(), any())).thenReturn(CompletableFuture.completedFuture(null));
    }

    private void publisher() {
        publisher = new KafkaSecurityEventPublisher(template, properties);
        publisher.setLocalAnalysis(analysedHere::add);
    }

    @Test
    void aSendRefusedBeforeItLeftIsAnalysedHere() {
        aTopicThatCannotBeUsed();
        publisher();

        publisher.publishGenericSecurityEvent(event("session-1"));

        Awaitility.await().untilAsserted(() -> assertThat(analysedHere).hasSize(1));
        assertThat(analysedHere.get(0).getUserId()).isEqualTo("alice");
    }

    @Test
    void aDeliveryThatFailedIsAnalysedHereOffTheProducersThread() {
        CompletableFuture<SendResult<String, Object>> delivery = new CompletableFuture<>();
        when(template.send(anyString(), anyString(), any())).thenReturn(delivery);
        when(template.send(anyString(), any())).thenReturn(CompletableFuture.completedFuture(null));
        List<String> threads = new CopyOnWriteArrayList<>();
        publisher = new KafkaSecurityEventPublisher(template, properties);
        publisher.setLocalAnalysis(event -> threads.add(Thread.currentThread().getName()));

        publisher.publishGenericSecurityEvent(event("session-1"));
        Awaitility.await().untilAsserted(() -> verify(template).send(anyString(), anyString(), any()));
        delivery.completeExceptionally(new TimeoutException("Expiring 1 record"));

        Awaitility.await().untilAsserted(() -> assertThat(threads).hasSize(1));
        assertThat(threads.get(0)).isEqualTo(KafkaSecurityEventPublisher.SENDER_THREAD);
    }

    @Test
    void anEventThatWaitedTooLongForTheBrokerIsAnalysedHere() {
        CountDownLatch release = new CountDownLatch(1);
        when(template.send(anyString(), anyString(), any())).thenAnswer(call -> {
            release.await();
            return CompletableFuture.completedFuture(null);
        });
        AdjustableClock clock = new AdjustableClock();
        publisher = new KafkaSecurityEventPublisher(template, properties, clock);
        publisher.setLocalAnalysis(analysedHere::add);

        publisher.publishGenericSecurityEvent(event("session-1"));
        Awaitility.await().untilAsserted(() -> verify(template).send(anyString(), anyString(), any()));
        publisher.publishGenericSecurityEvent(event("session-2"));
        clock.advance(KafkaSecurityEventPublisher.MAX_QUEUE_WAIT.plusSeconds(1));
        release.countDown();

        Awaitility.await().untilAsserted(() -> assertThat(analysedHere).hasSize(1));
        assertThat(analysedHere.get(0).getSessionId()).isEqualTo("session-2");
    }

    @Test
    void anEventKafkaTookIsNotAnalysedHere() {
        when(template.send(anyString(), anyString(), any())).thenReturn(CompletableFuture.completedFuture(null));
        publisher();

        publisher.publishGenericSecurityEvent(event("session-1"));

        Awaitility.await().untilAsserted(() ->
                assertThat(publisher.getStatistics()).containsEntry("publish_confirmed_count", 1L));
        assertThat(analysedHere).isEmpty();
    }

    @Test
    void anAnalysisThatFailsStopsNeitherTheNextEventNorTheDeadLetter() {
        aTopicThatCannotBeUsed();
        List<String> sessions = new CopyOnWriteArrayList<>();
        publisher = new KafkaSecurityEventPublisher(template, properties);
        publisher.setLocalAnalysis(event -> {
            sessions.add(event.getSessionId());
            throw new IllegalStateException("queue");
        });

        publisher.publishGenericSecurityEvent(event("session-1"));
        publisher.publishGenericSecurityEvent(event("session-2"));

        Awaitility.await().untilAsserted(() -> assertThat(sessions).containsExactly("session-1", "session-2"));
        Awaitility.await().untilAsserted(() ->
                assertThat(publisher.getStatistics()).containsEntry("dlq_dispatch_confirmed_count", 2L));
    }

    @Test
    void withoutAnAnalysisAFailedEventGoesOnlyToTheDeadLetter() {
        aTopicThatCannotBeUsed();
        publisher = new KafkaSecurityEventPublisher(template, properties);

        publisher.publishGenericSecurityEvent(event("session-1"));

        Awaitility.await().untilAsserted(() ->
                assertThat(publisher.getStatistics()).containsEntry("dlq_dispatch_confirmed_count", 1L));
    }

    @Test
    void anEventKeepsOneIdOnBothWays() {
        ArgumentCaptor<Object> sent = ArgumentCaptor.forClass(Object.class);
        when(template.send(anyString(), anyString(), sent.capture())).thenThrow(new KafkaException("Send failed"));
        when(template.send(anyString(), any())).thenReturn(CompletableFuture.completedFuture(null));
        publisher();

        publisher.publishGenericSecurityEvent(event("session-1"));

        Awaitility.await().untilAsserted(() -> assertThat(analysedHere).hasSize(1));
        ZeroTrustSpringEvent toTheBroker = (ZeroTrustSpringEvent) sent.getValue();
        assertThat(ZeroTrustSecurityEventConverter.convert(toTheBroker).getEventId())
                .isNotBlank()
                .isEqualTo(ZeroTrustSecurityEventConverter.convert(analysedHere.get(0)).getEventId());
    }

    @Test
    void anIdTheEventHasIsKept() {
        when(template.send(anyString(), anyString(), any())).thenThrow(new KafkaException("Send failed"));
        when(template.send(anyString(), any())).thenReturn(CompletableFuture.completedFuture(null));
        publisher();

        publisher.publishGenericSecurityEvent(ZeroTrustSpringEvent.builder(new Object())
                .category(ZeroTrustEventCategory.AUTHORIZATION).eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("alice").sessionId("session-1").payload(Map.of("eventId", "request-1")).build());

        Awaitility.await().untilAsserted(() -> assertThat(analysedHere).hasSize(1));
        assertThat((String) analysedHere.get(0).getPayloadValue("eventId")).isEqualTo("request-1");
    }

    /** An event that reached the broker after all, or came back from the dead letters, is the one already analysed. */
    @Test
    void theSameEventComingTwiceIsAnalysedOnce() {
        ZeroTrustSpringEvent event = KafkaSecurityEventPublisher.withEventId(event("session-1"));
        SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> SecurityEventContext.builder()
                .securityEvent(call.getArgument(0))
                .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED).build());
        SecurityPlaneAgent agent = new SecurityPlaneAgent(mock(SecurityMonitoringService.class),
                new InMemorySecurityContextDataStore(), mock(CentralAuditFacade.class), processor,
                new SecurityPlaneProperties(), Runnable::run);
        agent.initialize();

        agent.processSecurityEvent(ZeroTrustSecurityEventConverter.convert(event));
        agent.processSecurityEvent(ZeroTrustSecurityEventConverter.convert(event));

        verify(processor, times(1)).process(any(SecurityEvent.class));
        agent.shutdown();
    }
}
