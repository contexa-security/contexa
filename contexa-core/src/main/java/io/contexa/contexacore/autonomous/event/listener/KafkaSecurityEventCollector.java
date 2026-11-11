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
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.SecurityEventOrigin;
import io.contexa.contexacore.autonomous.event.SecurityEventTopics;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.header.Headers;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;


@Slf4j
public class KafkaSecurityEventCollector implements SecurityEventCollector {

    /** Q-26: on an event whose publication failed, so that it was analysed by the node that had it. */
    public static final String ANALYSED_ON_THE_PUBLISHING_NODE = "analysedOnThePublishingNode";

    private static final String RECORD_TOPIC = "kafka.topic";
    private static final String RECORD_PARTITION = "kafka.partition";
    private static final String RECORD_OFFSET = "kafka.offset";

    private final ObjectMapper objectMapper;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final SecurityKafkaProperties securityKafkaProperties;
    private final List<SecurityEventListener> listeners;
    /**
     * The recent events by id, with when they happened: only their number is read. PR-91: the events themselves are not
     * kept, since an analysed event holds its whole context.
     */
    private final Map<String, Instant> eventCache;
    private final AtomicLong eventCount;
    private final AtomicLong ackCount;
    private final AtomicLong errorCount;
    private final AtomicLong otherApplicationEventCount;
    private final AtomicLong redeliveryScheduledCount;
    private final AtomicLong dlqDispatchRequestedCount;
    private final AtomicLong dlqDispatchConfirmedCount;
    private final AtomicLong dlqDispatchFailedCount;
    private volatile boolean running;
    private volatile DecidedRecordAcknowledger decidedRecords;

    public KafkaSecurityEventCollector(ObjectMapper objectMapper,
                                       KafkaTemplate<String, Object> kafkaTemplate,
                                       SecurityKafkaProperties securityKafkaProperties) {
        this.objectMapper = objectMapper;
        this.kafkaTemplate = kafkaTemplate;
        this.securityKafkaProperties = securityKafkaProperties;
        this.listeners = new CopyOnWriteArrayList<>();
        this.eventCache = new ConcurrentHashMap<>();
        this.eventCount = new AtomicLong(0);
        this.ackCount = new AtomicLong(0);
        this.errorCount = new AtomicLong(0);
        this.otherApplicationEventCount = new AtomicLong(0);
        this.redeliveryScheduledCount = new AtomicLong(0);
        this.dlqDispatchRequestedCount = new AtomicLong(0);
        this.dlqDispatchConfirmedCount = new AtomicLong(0);
        this.dlqDispatchFailedCount = new AtomicLong(0);
        this.running = true;
    }

    /** Keeps each record unacknowledged until the analysis is done with it; without it, a record is acknowledged at once. */
    public void setDecidedRecordAcknowledger(DecidedRecordAcknowledger decidedRecords) {
        this.decidedRecords = decidedRecords;
    }

    @PostConstruct
    public void initialize() {
        running = true;
    }

    @PreDestroy
    public void shutdown() {
        running = false;
    }

    /** A record that carries no name of an application, as every record of an application without a name does. */
    public void consumeZeroTrustEvents(String message, String topic, int partition, long offset,
                                       Acknowledgment acknowledgment) {
        consumeZeroTrustEvents(message, topic, partition, offset, null, acknowledgment);
    }

    /**
     * The group is the application's own ({@code security-plane-consumer.<name>} for an application with a name), so that
     * the consumers of two applications on one cluster do not split the partitions between them; and a record is
     * analysed only by the application whose name it carries (see {@link SecurityEventOrigin}).
     * The id names the container and its consumer threads ("contexa-security-event-collector-0-C-1"). Without it the container is
     * numbered by the processor that serves it, "KafkaListenerEndpointContainer#0" as an application's first listener is, and where the
     * application turns Kafka listening on, that processor is the application's and the number is taken from its own listeners. The
     * group stays the one named here.
     */
    @KafkaListener(
            id = "contexa-security-event-collector",
            topicPattern = SecurityEventTopics.PATTERN,
            groupId = "#{T(io.contexa.contexacommon.store.ApplicationNamespace).consumerGroup("
                    + "'${security.plane.kafka.group-id:security-plane-consumer}')}",
            containerFactory = "contexaKafkaListenerContainerFactory"
    )
    public void consumeZeroTrustEvents(
            @Payload String message,
            @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
            @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
            @Header(KafkaHeaders.OFFSET) long offset,
            ConsumerRecord<?, ?> record,
            Acknowledgment acknowledgment) {

        if (!running) {
            log.warn("[KafkaCollector] Collector stopped, skipping event - topic: {}, offset: {}", topic, offset);
            return;
        }

        Headers headers = record != null ? record.headers() : null;
        if (!SecurityEventOrigin.isOwn(headers)) {
            skipEventOfAnotherApplication(topic, partition, offset, headers, acknowledgment);
            return;
        }

        try {
            ZeroTrustSpringEvent zeroTrustEvent = objectMapper.readValue(message, ZeroTrustSpringEvent.class);
            SecurityEvent event = ZeroTrustSecurityEventConverter.convert(zeroTrustEvent);

            event.addMetadata(RECORD_TOPIC, topic);
            event.addMetadata(RECORD_PARTITION, String.valueOf(partition));
            event.addMetadata(RECORD_OFFSET, String.valueOf(offset));
            event.addMetadata("zerotrust.category", zeroTrustEvent.getCategory().name());
            event.addMetadata("zerotrust.eventType", zeroTrustEvent.getEventType());
            event.addMetadata("ingestAt", System.currentTimeMillis());

            DecidedRecordAcknowledger decided = acknowledgment != null ? decidedRecords : null;
            if (decided != null) {
                // Before the hand-over: the analysis may be done with the event before it returns.
                decided.taken(topic, partition, offset, acknowledgment);
            }
            boolean settledLater = processEvent(event);
            eventCount.incrementAndGet();

            if (decided != null) {
                if (!settledLater) {
                    decided.settled(topic, partition, offset);
                }
            } else if (acknowledgment != null) {
                event.addMetadata("ackAt", System.currentTimeMillis());
                acknowledgment.acknowledge();
                ackCount.incrementAndGet();
            }

        } catch (Exception e) {
            log.error("[KafkaCollector] ERROR processing ZeroTrust event - topic: {}, offset: {}, error: {}",
                    topic, offset, e.getMessage(), e);
            errorCount.incrementAndGet();
            redeliveryScheduledCount.incrementAndGet();
            sendToDeadLetterQueueAsync(message, topic, partition, offset, e);
            throw new IllegalStateException("Kafka security event processing failed - redelivery scheduled", e);
        }
    }

    /**
     * A record of another application is not analysed here, and the offset moves on all the same: it is taken and settled
     * at once, so the commit goes past it in its place among the records of the partition, and a partition full of
     * another application's events never holds this one back.
     */
    private void skipEventOfAnotherApplication(String topic, int partition, long offset, Headers headers,
                                               Acknowledgment acknowledgment) {
        otherApplicationEventCount.incrementAndGet();
        if (log.isDebugEnabled()) {
            log.debug("[KafkaCollector] Skipping an event of another application - application: '{}', topic: {}, "
                    + "partition: {}, offset: {}", SecurityEventOrigin.nameIn(headers), topic, partition, offset);
        }
        DecidedRecordAcknowledger decided = acknowledgment != null ? decidedRecords : null;
        if (decided != null) {
            decided.taken(topic, partition, offset, acknowledgment);
            decided.settled(topic, partition, offset);
        } else if (acknowledgment != null) {
            acknowledgment.acknowledge();
            ackCount.incrementAndGet();
        }
    }

    /** The record of the event may be committed; an event that came from no record of this consumer changes nothing. */
    @Override
    public void settled(SecurityEvent event) {
        DecidedRecordAcknowledger decided = decidedRecords;
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        if (decided == null || metadata == null || metadata.containsKey(ANALYSED_ON_THE_PUBLISHING_NODE)) {
            return;
        }
        Object topic = metadata.get(RECORD_TOPIC);
        Object partition = metadata.get(RECORD_PARTITION);
        Object offset = metadata.get(RECORD_OFFSET);
        if (topic != null && partition != null && offset != null) {
            decided.settled(topic.toString(), Integer.parseInt(partition.toString()), Long.parseLong(offset.toString()));
        }
    }

    /**
     * Q-26: hands an event Kafka did not take to the listeners of this node, as a consumed event is handed to them. Its
     * id is the one it was published under, so a copy that reached the broker after all is the same event to the
     * analysis.
     */
    public void analyseHere(ZeroTrustSpringEvent zeroTrustEvent) {
        SecurityEvent event = ZeroTrustSecurityEventConverter.convert(zeroTrustEvent);
        event.addMetadata("zerotrust.category", zeroTrustEvent.getCategory().name());
        event.addMetadata("zerotrust.eventType", zeroTrustEvent.getEventType());
        event.addMetadata("ingestAt", System.currentTimeMillis());
        event.addMetadata(ANALYSED_ON_THE_PUBLISHING_NODE, true);
        processEvent(event);
        eventCount.incrementAndGet();
    }

    @Override
    public void registerListener(SecurityEventListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    @Override
    public void unregisterListener(SecurityEventListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    /** Hands the event to the listeners; true when one of them goes on with it and will say when it is done. */
    private boolean processEvent(SecurityEvent event) {
        if (!running || event == null) {
            return false;
        }

        if (event.getEventId() == null) {
            event.setEventId(UUID.randomUUID().toString());
        }

        eventCache.put(event.getEventId(), event.getTimestamp() != null ? event.getTimestamp() : Instant.EPOCH);

        if (eventCache.size() > 10_000) {
            eventCache.entrySet().stream()
                    .sorted(Map.Entry.comparingByValue())
                    .limit(1_000)
                    .map(Map.Entry::getKey)
                    .forEach(eventCache::remove);
        }

        boolean settledLater = false;
        RuntimeException listenerFailure = null;
        for (SecurityEventListener listener : listeners) {
            try {
                if (listener.isActive()) {
                    listener.onSecurityEvent(event);
                    settledLater |= listener.settlesItsEvents();
                }
            } catch (Exception e) {
                log.error("[KafkaCollector] Listener {} failed to process event {}: {}",
                        listener.getListenerName(), event.getEventId(), e.getMessage(), e);
                if (listenerFailure == null) {
                    listenerFailure = new IllegalStateException(
                            "Listener dispatch failed for event " + event.getEventId(), e);
                }
            }
        }

        if (listenerFailure != null) {
            throw listenerFailure;
        }
        return settledLater;
    }

    @Override
    public Map<String, Object> getStatistics() {
        DecidedRecordAcknowledger decided = decidedRecords;
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_events", eventCount.get());
        stats.put("ack_count", ackCount.get() + (decided != null ? decided.acknowledgments() : 0L));
        stats.put("undecided_records", decided != null ? decided.undecidedRecords() : 0L);
        stats.put("commit_passed_undecided_count", decided != null ? decided.passedUndecided() : 0L);
        stats.put("error_count", errorCount.get());
        stats.put("other_application_events_skipped", otherApplicationEventCount.get());
        stats.put("redelivery_scheduled_count", redeliveryScheduledCount.get());
        stats.put("dlq_dispatch_requested_count", dlqDispatchRequestedCount.get());
        stats.put("dlq_dispatch_confirmed_count", dlqDispatchConfirmedCount.get());
        stats.put("dlq_dispatch_failed_count", dlqDispatchFailedCount.get());
        stats.put("cache_size", eventCache.size());
        stats.put("listener_count", listeners.size());
        stats.put("running", running);
        return stats;
    }

    private void sendToDeadLetterQueueAsync(String message, String topic, int partition, long offset, Exception exception) {
        try {
            Map<String, Object> dlqMessage = new HashMap<>();
            dlqMessage.put("originalMessage", message);
            dlqMessage.put("originalTopic", topic);
            dlqMessage.put("partition", partition);
            dlqMessage.put("offset", offset);
            dlqMessage.put("errorMessage", exception.getMessage());
            dlqMessage.put("errorType", exception.getClass().getName());
            dlqMessage.put("timestamp", System.currentTimeMillis());
            dlqMessage.put("stackTrace", getStackTraceAsString(exception));

            String dlqTopic = securityKafkaProperties.getTopic().getDlq();
            String dlqJson = objectMapper.writeValueAsString(dlqMessage);
            dlqDispatchRequestedCount.incrementAndGet();
            SecurityEventOrigin.send(kafkaTemplate, dlqTopic, null, dlqJson).whenComplete((result, dlqError) -> {
                if (dlqError == null) {
                    dlqDispatchConfirmedCount.incrementAndGet();
                    log.warn("[KafkaCollector] DLQ dispatch confirmed - topic: {}, partition: {}, offset: {}",
                            topic, partition, offset);
                    return;
                }
                dlqDispatchFailedCount.incrementAndGet();
                log.error("[KafkaCollector] DLQ dispatch failed - original topic: {}, partition: {}, offset: {}",
                        topic, partition, offset, dlqError);
            });
        } catch (Exception e) {
            dlqDispatchFailedCount.incrementAndGet();
            log.error("[KafkaCollector] Failed to schedule DLQ message - offset: {}", offset, e);
        }
    }

    private String getStackTraceAsString(Exception e) {
        if (e == null) {
            return "";
        }
        try (StringWriter sw = new StringWriter();
             PrintWriter pw = new PrintWriter(sw)) {
            e.printStackTrace(pw);
            return sw.toString();
        } catch (IOException ignored) {
            return e.toString();
        }
    }
}
