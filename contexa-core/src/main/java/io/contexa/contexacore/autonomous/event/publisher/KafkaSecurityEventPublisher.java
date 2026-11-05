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

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.SecurityEventTopics;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;

import io.contexa.contexacore.properties.SecurityKafkaProperties;
import io.contexa.contexacore.util.ErrorLogThrottle;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.kafka.core.KafkaTemplate;

import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Hands security events to Kafka from a thread of its own (PR-79). A producer waits up to its limit for a topic it
 * cannot find or a broker it cannot reach, and a publication is made on the thread of the request it is for, so that
 * wait and a send's failure stay here: the request goes on at once. Events leave one by one in the order they came.
 * <p>
 * Q-26: an event Kafka did not take, or that waited past a send's own limit, is counted, reported and analysed on this
 * node, as standalone analyses it, so a topic that cannot be used costs no decision. Every event leaves with an id of
 * its own: one that reached the broker although its send failed, or that comes back from the dead letters, is the same
 * event to the agent's processing claim and to the decision on record, on any node, and is not analysed twice. Only
 * past the queue's capacity, where nothing may hold the request's thread, is an event dropped, counted and reported.
 */
@Slf4j
public class KafkaSecurityEventPublisher implements SecurityEventPublisher, DisposableBean {

    /** Far more than a broker that answers ever leaves waiting: a send that finds its topic takes microseconds. */
    static final int QUEUE_CAPACITY = 1024;
    /** A send's own limit (the producer's delivery timeout): later, the event would be analysed as a moment long gone. */
    static final Duration MAX_QUEUE_WAIT = Duration.ofSeconds(10);
    static final String SENDER_THREAD = "contexa-kafka-event-sender";
    private static final String EVENT_ID = "eventId";
    private static final Duration SHUTDOWN_WAIT = Duration.ofSeconds(5);
    private static final Duration FAILURE_LOG_INTERVAL = Duration.ofMinutes(1);

    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final SecurityKafkaProperties securityKafkaProperties;
    private final Clock clock;
    private final ExecutorService sender = newSender();
    private final ErrorLogThrottle failureLogThrottle = new ErrorLogThrottle(FAILURE_LOG_INTERVAL);
    private final AtomicLong publishRequestedCount = new AtomicLong(0);
    private final AtomicLong publishConfirmedCount = new AtomicLong(0);
    private final AtomicLong publishFailedCount = new AtomicLong(0);
    private final AtomicLong dlqDispatchRequestedCount = new AtomicLong(0);
    private final AtomicLong dlqDispatchConfirmedCount = new AtomicLong(0);
    private final AtomicLong dlqDispatchFailedCount = new AtomicLong(0);
    private final AtomicLong analysedHereCount = new AtomicLong(0);
    private volatile Consumer<ZeroTrustSpringEvent> localAnalysis;

    public KafkaSecurityEventPublisher(KafkaTemplate<String, Object> kafkaTemplate,
                                       SecurityKafkaProperties securityKafkaProperties) {
        this(kafkaTemplate, securityKafkaProperties, Clock.systemUTC());
    }

    KafkaSecurityEventPublisher(KafkaTemplate<String, Object> kafkaTemplate,
                                SecurityKafkaProperties securityKafkaProperties, Clock clock) {
        this.kafkaTemplate = kafkaTemplate;
        this.securityKafkaProperties = securityKafkaProperties;
        this.clock = clock;
    }

    /** Q-26: where an event Kafka did not take is analysed. */
    public void setLocalAnalysis(Consumer<ZeroTrustSpringEvent> localAnalysis) {
        this.localAnalysis = localAnalysis;
    }

    /** The event with an id of its own, which it keeps however it reaches the analysis (Q-26). */
    static ZeroTrustSpringEvent withEventId(ZeroTrustSpringEvent event) {
        Object eventId = event.getPayload().get(EVENT_ID);
        if (eventId != null && !eventId.toString().isBlank()) {
            return event;
        }
        Map<String, Object> payload = new HashMap<>(event.getPayload());
        payload.put(EVENT_ID, UUID.randomUUID().toString());
        return ZeroTrustSpringEvent.builder(event.getSource())
                .category(event.getCategory())
                .eventType(event.getEventType())
                .userId(event.getUserId())
                .sessionId(event.getSessionId())
                .clientIp(event.getClientIp())
                .userAgent(event.getUserAgent())
                .resource(event.getResource())
                .eventTimestamp(event.getEventTimestamp())
                .payload(payload)
                .build();
    }

    private static ExecutorService newSender() {
        return new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(QUEUE_CAPACITY), task -> {
            Thread thread = new Thread(task, SENDER_THREAD);
            thread.setDaemon(true);
            return thread;
        });
    }

    @Override
    public void publishGenericSecurityEvent(ZeroTrustSpringEvent event) {
        publishRequestedCount.incrementAndGet();
        long queuedAt = clock.millis();
        ZeroTrustSpringEvent identified = withEventId(event);
        try {
            sender.execute(() -> send(identified, queuedAt));
        } catch (RejectedExecutionException noRoom) {
            publishFailedCount.incrementAndGet();
            reportFailure(event, "the publisher's queue is full or shut down", queuedAt, noRoom);
        }
    }

    private void send(ZeroTrustSpringEvent event, long queuedAt) {
        if (clock.millis() - queuedAt > MAX_QUEUE_WAIT.toMillis()) {
            publishFailedCount.incrementAndGet();
            reportFailure(event, "it waited too long for the broker", queuedAt, null);
            analyseHere(event);
            return;
        }
        try {
            String topic = SecurityEventTopics.of(event.getCategory(), event.getEventType());
            kafkaTemplate.send(topic, generateEventKey(event), event).whenComplete((result, failure) -> {
                if (failure != null) {
                    failed(event, queuedAt, failure);
                    return;
                }
                publishConfirmedCount.incrementAndGet();
            });
        } catch (RuntimeException refused) {
            // KafkaTemplate throws what the producer refused before the event left: a topic it could not find in time.
            failed(event, queuedAt, refused);
        }
    }

    /**
     * The producer tells a delivery's failure on its own thread, which a send that waits would stop, so the analysis
     * and the dead letter leave from here.
     */
    private void failed(ZeroTrustSpringEvent event, long queuedAt, Throwable failure) {
        publishFailedCount.incrementAndGet();
        reportFailure(event, failure.getMessage(), queuedAt, failure);
        Runnable afterTheFailure = () -> {
            analyseHere(event);
            sendToDeadLetterQueueAsync(event, failure);
        };
        if (SENDER_THREAD.equals(Thread.currentThread().getName())) {
            afterTheFailure.run();
            return;
        }
        try {
            sender.execute(afterTheFailure);
        } catch (RejectedExecutionException noRoom) {
            dlqDispatchRequestedCount.incrementAndGet();
            dlqDispatchFailedCount.incrementAndGet();
        }
    }

    /** Q-26: the event goes to this node's analysis; a failure there stops neither the dead letter nor the next event. */
    private void analyseHere(ZeroTrustSpringEvent event) {
        Consumer<ZeroTrustSpringEvent> analysis = localAnalysis;
        if (analysis == null) {
            return;
        }
        try {
            analysis.accept(event);
            analysedHereCount.incrementAndGet();
        } catch (RuntimeException failure) {
            log.error("[KafkaPublisher] An event Kafka did not take could not reach this node's analysis - category={}, "
                    + "type={}", event.getCategory(), event.getEventType(), failure);
        }
    }

    private void reportFailure(ZeroTrustSpringEvent event, String reason, long queuedAt, Throwable failure) {
        long suppressed = failureLogThrottle.tryAcquire();
        if (suppressed == ErrorLogThrottle.SUPPRESSED) {
            return;
        }
        log.error("[KafkaPublisher] Failed to publish ZeroTrust event - category={}, type={}, error: {}, duration={}ms, "
                        + "similarFailuresSinceLastReport={}",
                event.getCategory(), event.getEventType(), reason, clock.millis() - queuedAt, suppressed, failure);
    }

    private String generateEventKey(ZeroTrustSpringEvent event) {
        if (event.getSessionId() != null && !event.getSessionId().isEmpty()) {
            return event.getSessionId();
        }
        if (event.getUserId() != null && !event.getUserId().isEmpty()) {
            return event.getUserId();
        }
        return "unknown-" + System.currentTimeMillis();
    }

    private void sendToDeadLetterQueueAsync(Object event, Throwable exception) {
        try {
            DeadLetterEvent dlqEvent = DeadLetterEvent.builder()
                    .originalEvent(event)
                    .errorMessage(exception.getMessage())
                    .errorType(exception.getClass().getName())
                    .build();

            dlqDispatchRequestedCount.incrementAndGet();
            kafkaTemplate.send(securityKafkaProperties.getTopic().getDlq(), dlqEvent)
                    .whenComplete((result, dlqError) -> {
                        if (dlqError == null) {
                            dlqDispatchConfirmedCount.incrementAndGet();
                            log.debug("Event sent to Dead Letter Queue: {}", event);
                            return;
                        }
                        dlqDispatchFailedCount.incrementAndGet();
                        log.error("Failed to dispatch event to Dead Letter Queue", dlqError);
                    });
        } catch (Exception e) {
            dlqDispatchFailedCount.incrementAndGet();
            log.error("Failed to send event to Dead Letter Queue", e);
        }
    }

    /** Lets what is waiting leave, within a limit: a broker that is gone does not hold the application's shutdown. */
    @Override
    public void destroy() {
        sender.shutdown();
        try {
            if (!sender.awaitTermination(SHUTDOWN_WAIT.toMillis(), TimeUnit.MILLISECONDS)) {
                int dropped = sender.shutdownNow().size();
                publishFailedCount.addAndGet(dropped);
                log.error("[KafkaPublisher] {} security events were not published before the shutdown", dropped);
            }
        } catch (InterruptedException interrupted) {
            sender.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("publish_requested_count", publishRequestedCount.get());
        stats.put("publish_confirmed_count", publishConfirmedCount.get());
        stats.put("publish_failed_count", publishFailedCount.get());
        stats.put("dlq_dispatch_requested_count", dlqDispatchRequestedCount.get());
        stats.put("dlq_dispatch_confirmed_count", dlqDispatchConfirmedCount.get());
        stats.put("dlq_dispatch_failed_count", dlqDispatchFailedCount.get());
        stats.put("analysed_here_count", analysedHereCount.get());
        return stats;
    }

    @Data
    @Builder
    private static class DeadLetterEvent {
        private Object originalEvent;
        private String errorMessage;
        private String errorType;
        @Builder.Default
        private long timestamp = System.currentTimeMillis();
    }
}
