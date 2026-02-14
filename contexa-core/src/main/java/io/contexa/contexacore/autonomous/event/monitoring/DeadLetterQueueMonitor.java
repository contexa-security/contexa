package io.contexa.contexacore.autonomous.event.monitoring;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class DeadLetterQueueMonitor {

    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final MeterRegistry meterRegistry;
    private final SecurityKafkaProperties securityKafkaProperties;

    private final Map<String, DLQMessage> dlqMessages = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> errorCountByType = new ConcurrentHashMap<>();

    private Counter dlqMessageCounter;
    private Counter retrySuccessCounter;
    private Counter retryFailureCounter;
    private Counter permanentFailureCounter;
    private Timer retryLatencyTimer;

    @PostConstruct
    public void initialize() {
        
        dlqMessageCounter = Counter.builder("dlq.messages.received")
            .description("Total number of messages received in DLQ")
            .register(meterRegistry);

        retrySuccessCounter = Counter.builder("dlq.retry.success")
            .description("Number of successful retries from DLQ")
            .register(meterRegistry);

        retryFailureCounter = Counter.builder("dlq.retry.failure")
            .description("Number of failed retry attempts")
            .register(meterRegistry);

        permanentFailureCounter = Counter.builder("dlq.permanent.failure")
            .description("Number of permanently failed messages")
            .register(meterRegistry);

        retryLatencyTimer = Timer.builder("dlq.retry.latency")
            .description("Latency of retry operations")
            .register(meterRegistry);

            }

    @KafkaListener(topics = "${security.kafka.topic.dlq:security-events-dlq}",
                   groupId = "dlq-monitor-group",
                   containerFactory = "kafkaListenerContainerFactory")
    public void consumeDLQMessage(
            @Payload String payload,
            @Header(KafkaHeaders.RECEIVED_KEY) String key,
            @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
            @Header(value = "original_topic", required = false) String originalTopic,
            @Header(value = "error_message", required = false) String errorMessage,
            @Header(value = "retry_count", required = false, defaultValue = "0") int retryCount) {

        dlqMessageCounter.increment();

        String messageId = UUID.randomUUID().toString();
        DLQMessage dlqMessage = DLQMessage.builder()
            .messageId(messageId)
            .originalTopic(originalTopic)
            .payload(payload)
            .errorMessage(errorMessage)
            .retryCount(retryCount)
            .receivedAt(Instant.now())
            .build();

        dlqMessages.put(messageId, dlqMessage);

        String errorType = extractErrorType(errorMessage);
        errorCountByType.computeIfAbsent(errorType, k -> new AtomicLong()).incrementAndGet();

        log.error("DLQ message received: messageId={}, originalTopic={}, retryCount={}, error={}",
            messageId, originalTopic, retryCount, errorMessage);

        scheduleRetry(dlqMessage);
    }

    private void scheduleRetry(DLQMessage message) {
        if (message.getRetryCount() >= securityKafkaProperties.getDlq().getMaxRetries()) {
            handlePermanentFailure(message);
            return;
        }

        long backoffDelay = securityKafkaProperties.getDlq().getRetryDelayMs() * (long) Math.pow(2, message.getRetryCount());

        message.setNextRetryAt(Instant.now().plusMillis(backoffDelay));
    }

    @Scheduled(fixedDelayString = "${security.kafka.dlq.retry-delay-ms:5000}")
    public void processRetries() {
        Instant now = Instant.now();

        dlqMessages.values().stream()
            .filter(msg -> msg.getNextRetryAt() != null && msg.getNextRetryAt().isBefore(now))
            .forEach(this::attemptRetry);
    }

    private void attemptRetry(DLQMessage message) {
        
        Instant start = Instant.now();

        try {
            
            kafkaTemplate.send(message.getOriginalTopic(), message.getPayload())
                .whenComplete((result, ex) -> {
                    long latency = Duration.between(start, Instant.now()).toMillis();
                    retryLatencyTimer.record(latency, TimeUnit.MILLISECONDS);

                    if (ex == null) {
                        retrySuccessCounter.increment();
                        dlqMessages.remove(message.getMessageId());
                                            } else {
                        retryFailureCounter.increment();
                        message.incrementRetryCount();
                        log.error("Retry failed: messageId={}, error={}",
                            message.getMessageId(), ex.getMessage(), ex);
                        scheduleRetry(message);
                    }
                });

        } catch (Exception e) {
            retryFailureCounter.increment();
            message.incrementRetryCount();
            log.error("Retry exception: messageId={}", message.getMessageId(), e);
            scheduleRetry(message);
        }
    }

    private void handlePermanentFailure(DLQMessage message) {
        permanentFailureCounter.increment();

        log.error("PERMANENT FAILURE: messageId={}, originalTopic={}, retryCount={}, error={}",
            message.getMessageId(), message.getOriginalTopic(),
            message.getRetryCount(), message.getErrorMessage());

        sendAlert(message);

        archivePermanentFailure(message);

        dlqMessages.remove(message.getMessageId());
    }

    private void sendAlert(DLQMessage message) {
        log.error("ALERT: Permanent DLQ failure - messageId={}, topic={}",
            message.getMessageId(), message.getOriginalTopic());

    }

    private void archivePermanentFailure(DLQMessage message) {
        
            }

    @Scheduled(fixedRate = 60000)
    public void generateMonitoringReport() {
        int currentDLQSize = dlqMessages.size();

        if (currentDLQSize > securityKafkaProperties.getDlq().getAlertThreshold()) {
            log.error("DLQ size exceeded threshold: {} > {}", currentDLQSize, securityKafkaProperties.getDlq().getAlertThreshold());
            sendThresholdAlert(currentDLQSize);
        }

        meterRegistry.gauge("dlq.messages.current", currentDLQSize);
    }

    private void sendThresholdAlert(int currentSize) {
        log.error("ALERT: DLQ size threshold exceeded - current={}, threshold={}",
            currentSize, securityKafkaProperties.getDlq().getAlertThreshold());

    }

    private String extractErrorType(String errorMessage) {
        if (errorMessage == null) return "UNKNOWN";

        if (errorMessage.contains("Timeout")) return "TIMEOUT";
        if (errorMessage.contains("Connection")) return "CONNECTION";
        if (errorMessage.contains("Serialization")) return "SERIALIZATION";
        if (errorMessage.contains("Authorization")) return "AUTHORIZATION";

        return "OTHER";
    }

    @lombok.Data
    @lombok.Builder
    private static class DLQMessage {
        private String messageId;
        private String originalTopic;
        private String payload;
        private String errorMessage;
        private int retryCount;
        private Instant receivedAt;
        private Instant nextRetryAt;

        public void incrementRetryCount() {
            this.retryCount++;
        }
    }
}
