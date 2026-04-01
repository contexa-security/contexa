package io.contexa.contexacore.autonomous.event.listener;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class KafkaSecurityEventCollector implements SecurityEventCollector {

    private final ObjectMapper objectMapper;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final SecurityKafkaProperties securityKafkaProperties;
    private final List<SecurityEventListener> listeners;
    private final Map<String, SecurityEvent> eventCache;
    private final AtomicLong eventCount;
    private final AtomicLong ackCount;
    private final AtomicLong errorCount;
    private final AtomicLong redeliveryScheduledCount;
    private final AtomicLong dlqDispatchRequestedCount;
    private final AtomicLong dlqDispatchConfirmedCount;
    private final AtomicLong dlqDispatchFailedCount;
    private volatile boolean running;

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
        this.redeliveryScheduledCount = new AtomicLong(0);
        this.dlqDispatchRequestedCount = new AtomicLong(0);
        this.dlqDispatchConfirmedCount = new AtomicLong(0);
        this.dlqDispatchFailedCount = new AtomicLong(0);
        this.running = true;
    }

    @PostConstruct
    public void initialize() {
        running = true;
    }

    @PreDestroy
    public void shutdown() {
        running = false;
    }

    @KafkaListener(
            topicPattern = "security\\.events\\..*",
            groupId = "${security.plane.kafka.group-id:security-plane-consumer}",
            containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeZeroTrustEvents(
            @Payload String message,
            @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
            @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
            @Header(KafkaHeaders.OFFSET) long offset,
            Acknowledgment acknowledgment) {

        if (!running) {
            log.warn("[KafkaCollector] Collector stopped, skipping event - topic: {}, offset: {}", topic, offset);
            return;
        }

        try {
            ZeroTrustSpringEvent zeroTrustEvent = objectMapper.readValue(message, ZeroTrustSpringEvent.class);
            SecurityEvent event = ZeroTrustSecurityEventConverter.convert(zeroTrustEvent);

            event.addMetadata("kafka.topic", topic);
            event.addMetadata("kafka.partition", String.valueOf(partition));
            event.addMetadata("kafka.offset", String.valueOf(offset));
            event.addMetadata("zerotrust.category", zeroTrustEvent.getCategory().name());
            event.addMetadata("zerotrust.eventType", zeroTrustEvent.getEventType());
            event.addMetadata("ingestAt", System.currentTimeMillis());

            processEvent(event);
            eventCount.incrementAndGet();

            if (acknowledgment != null) {
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

    private void processEvent(SecurityEvent event) {
        if (!running || event == null) {
            return;
        }

        if (event.getEventId() == null) {
            event.setEventId(UUID.randomUUID().toString());
        }

        eventCache.put(event.getEventId(), event);

        if (eventCache.size() > 10_000) {
            eventCache.entrySet().stream()
                    .sorted(Map.Entry.comparingByValue(Comparator.comparing(SecurityEvent::getTimestamp)))
                    .limit(1_000)
                    .map(Map.Entry::getKey)
                    .forEach(eventCache::remove);
        }

        if (listeners.isEmpty()) {
            return;
        }

        RuntimeException listenerFailure = null;
        for (SecurityEventListener listener : listeners) {
            try {
                if (listener.isActive()) {
                    listener.onSecurityEvent(event);
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
    }

    @Override
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_events", eventCount.get());
        stats.put("ack_count", ackCount.get());
        stats.put("error_count", errorCount.get());
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
            kafkaTemplate.send(dlqTopic, dlqJson).whenComplete((result, dlqError) -> {
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
        java.io.StringWriter sw = new java.io.StringWriter();
        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }
}
