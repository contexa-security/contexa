package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.BatchSecurityEventListener;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class SecurityMonitoringService {

    private static final Logger log = LoggerFactory.getLogger(SecurityMonitoringService.class);

    @FunctionalInterface
    public interface SecurityEventBatchProcessor {
        void processBatch(List<SecurityEvent> events);
    }

    private final KafkaSecurityEventCollector kafkaCollector;
    private final AtomicLong eventCounter;

    private volatile SecurityEventBatchProcessor batchProcessor;

    public SecurityMonitoringService(KafkaSecurityEventCollector kafkaCollector) {
        this.kafkaCollector = kafkaCollector;
        this.eventCounter = new AtomicLong(0);
    }

    public void setBatchProcessor(SecurityEventBatchProcessor processor) {
        this.batchProcessor = processor;
    }

    @PostConstruct
    public void initialize() {
        kafkaCollector.registerListener(new DefaultBatchEventListener());
    }

    private SecurityEvent preprocessEvent(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        eventCounter.incrementAndGet();
        return event;
    }

    private class DefaultBatchEventListener implements BatchSecurityEventListener {

        @Override
        public void onBatchEvents(List<SecurityEvent> events) {
            if (events == null || events.isEmpty()) {
                return;
            }
            SecurityMonitoringService.log.error("[DirectBatchListener] Received batch of {} events", events.size());
            List<SecurityEvent> processedList = events.stream()
                    .map(DefaultBatchEventListener.this::preprocessEventSafe)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            if (processedList.isEmpty()) {
                SecurityMonitoringService.log.error("[DirectBatchListener] All events filtered during preprocessing");
                return;
            }
            if (batchProcessor != null) {
                try {
                    batchProcessor.processBatch(processedList);
                } catch (Exception e) {
                    SecurityMonitoringService.log.error("[DirectBatchListener] Failed to process batch", e);
                    throw new RuntimeException("Batch processing failed", e);
                }
            } else {
                SecurityMonitoringService.log.error("[DirectBatchListener] No batch processor registered, {} events dropped", processedList.size());
            }
        }

        @Override
        public void onSecurityEvent(SecurityEvent event) {
            onBatchEvents(List.of(event));
        }

        @Override
        public String getListenerName() {
            return "DirectBatchListener";
        }

        private SecurityEvent preprocessEventSafe(SecurityEvent event) {
            try {
                return preprocessEvent(event);
            } catch (Exception e) {
                SecurityMonitoringService.log.error("[DirectBatchListener] Error preprocessing event: {}", event.getEventId(), e);
                return null;
            }
        }
    }
}