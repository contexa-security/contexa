package io.contexa.contexacore.autonomous.event.monitoring;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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

/**
 * Dead Letter Queue 모니터링 시스템
 *
 * 기능:
 * - DLQ 메시지 실시간 모니터링
 * - 재시도 전략 (지수 백오프)
 * - 메트릭 수집 및 알림
 * - 자동 복구 메커니즘
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DeadLetterQueueMonitor {

    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final MeterRegistry meterRegistry;

    @Value("${security.kafka.dlq.max-retries:3}")
    private int maxRetries;

    @Value("${security.kafka.dlq.retry-delay-ms:5000}")
    private long retryDelayMs;

    @Value("${security.kafka.dlq.alert-threshold:10}")
    private int alertThreshold;

    // DLQ 메시지 추적
    private final Map<String, DLQMessage> dlqMessages = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> errorCountByType = new ConcurrentHashMap<>();

    // Metrics
    private Counter dlqMessageCounter;
    private Counter retrySuccessCounter;
    private Counter retryFailureCounter;
    private Counter permanentFailureCounter;
    private Timer retryLatencyTimer;

    @PostConstruct
    public void initialize() {
        // Metrics 초기화
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

        log.info("DLQ Monitor initialized: maxRetries={}, retryDelayMs={}, alertThreshold={}",
            maxRetries, retryDelayMs, alertThreshold);
    }

    /**
     * DLQ 메시지 수신 및 처리
     */
    @KafkaListener(topics = "${security.kafka.topic.dlq:security-dlq}",
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

        // 에러 타입별 카운트
        String errorType = extractErrorType(errorMessage);
        errorCountByType.computeIfAbsent(errorType, k -> new AtomicLong()).incrementAndGet();

        log.warn("DLQ message received: messageId={}, originalTopic={}, retryCount={}, error={}",
            messageId, originalTopic, retryCount, errorMessage);

        // 재시도 스케줄링
        scheduleRetry(dlqMessage);
    }

    /**
     * 재시도 스케줄링 (지수 백오프)
     */
    private void scheduleRetry(DLQMessage message) {
        if (message.getRetryCount() >= maxRetries) {
            handlePermanentFailure(message);
            return;
        }

        // 지수 백오프: delay * 2^retryCount
        long backoffDelay = retryDelayMs * (long) Math.pow(2, message.getRetryCount());

        log.info("Scheduling retry for messageId={}, retryCount={}, delay={}ms",
            message.getMessageId(), message.getRetryCount(), backoffDelay);

        // 실제 구현에서는 Spring Task Scheduler 또는 Quartz 사용
        // 여기서는 간단히 표현
        message.setNextRetryAt(Instant.now().plusMillis(backoffDelay));
    }

    /**
     * 주기적 재시도 실행 (1분마다)
     */
//    @Scheduled(fixedRate = 60000)
    public void processRetries() {
        Instant now = Instant.now();

        dlqMessages.values().stream()
            .filter(msg -> msg.getNextRetryAt() != null && msg.getNextRetryAt().isBefore(now))
            .forEach(this::attemptRetry);
    }

    /**
     * 재시도 실행
     */
    private void attemptRetry(DLQMessage message) {
        log.info("Attempting retry: messageId={}, retryCount={}",
            message.getMessageId(), message.getRetryCount());

        Instant start = Instant.now();

        try {
            // 원본 토픽으로 재전송
            kafkaTemplate.send(message.getOriginalTopic(), message.getPayload())
                .whenComplete((result, ex) -> {
                    long latency = Duration.between(start, Instant.now()).toMillis();
                    retryLatencyTimer.record(latency, TimeUnit.MILLISECONDS);

                    if (ex == null) {
                        retrySuccessCounter.increment();
                        dlqMessages.remove(message.getMessageId());
                        log.info("Retry successful: messageId={}, latency={}ms",
                            message.getMessageId(), latency);
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

    /**
     * 영구 실패 처리
     */
    private void handlePermanentFailure(DLQMessage message) {
        permanentFailureCounter.increment();

        log.error("PERMANENT FAILURE: messageId={}, originalTopic={}, retryCount={}, error={}",
            message.getMessageId(), message.getOriginalTopic(),
            message.getRetryCount(), message.getErrorMessage());

        // 알림 전송 (Slack, Email 등)
        sendAlert(message);

        // 영구 실패 저장소로 이동 (분석 및 수동 처리용)
        archivePermanentFailure(message);

        dlqMessages.remove(message.getMessageId());
    }

    /**
     * 알림 전송
     */
    private void sendAlert(DLQMessage message) {
        log.error("ALERT: Permanent DLQ failure - messageId={}, topic={}",
            message.getMessageId(), message.getOriginalTopic());

        // TODO: Slack, Email, PagerDuty 등 실제 알림 구현
    }

    /**
     * 영구 실패 아카이빙
     */
    private void archivePermanentFailure(DLQMessage message) {
        // TODO: 데이터베이스 또는 별도 Kafka 토픽에 저장
        log.info("Archiving permanent failure: messageId={}", message.getMessageId());
    }

    /**
     * 주기적 모니터링 리포트 (5분마다)
     */
//    @Scheduled(fixedRate = 300000)
    public void generateMonitoringReport() {
        int currentDLQSize = dlqMessages.size();

        log.info("=== DLQ Monitoring Report ===");
        log.info("Current DLQ size: {}", currentDLQSize);
        log.info("Error types: {}", errorCountByType);

        // 임계값 초과 시 경고
        if (currentDLQSize > alertThreshold) {
            log.warn("DLQ size exceeded threshold: {} > {}", currentDLQSize, alertThreshold);
            sendThresholdAlert(currentDLQSize);
        }

        // 메트릭 게이지 업데이트
        meterRegistry.gauge("dlq.messages.current", currentDLQSize);
    }

    /**
     * 임계값 초과 알림
     */
    private void sendThresholdAlert(int currentSize) {
        log.error("ALERT: DLQ size threshold exceeded - current={}, threshold={}",
            currentSize, alertThreshold);

        // TODO: 실제 알림 구현
    }

    /**
     * 에러 타입 추출
     */
    private String extractErrorType(String errorMessage) {
        if (errorMessage == null) return "UNKNOWN";

        if (errorMessage.contains("Timeout")) return "TIMEOUT";
        if (errorMessage.contains("Connection")) return "CONNECTION";
        if (errorMessage.contains("Serialization")) return "SERIALIZATION";
        if (errorMessage.contains("Authorization")) return "AUTHORIZATION";

        return "OTHER";
    }

    /**
     * DLQ 메시지 모델
     */
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
