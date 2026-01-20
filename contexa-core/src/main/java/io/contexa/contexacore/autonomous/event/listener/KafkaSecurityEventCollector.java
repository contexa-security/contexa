package io.contexa.contexacore.autonomous.event.listener;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Kafka 기반 보안 이벤트 수집기
 *
 * AI Native v14.0: ZeroTrustSpringEvent로 통일
 *
 * 모든 보안 이벤트를 ZeroTrustSpringEvent 형식으로 수신합니다.
 * - 인가 이벤트: security.events.authorization.*
 * - 인증 성공 이벤트: security.events.authentication.success
 * - 인증 실패 이벤트: security.events.authentication.failure
 */
@Slf4j
public class KafkaSecurityEventCollector {

    @Value("${security.plane.kafka.bootstrap-servers:localhost:9092}")
    private String bootstrapServers;

    @Value("${security.plane.kafka.group-id:security-plane-consumer}")
    private String groupId;

    private final ObjectMapper objectMapper;
    private final List<SecurityEventListener> listeners;
    private final Map<String, SecurityEvent> eventCache;
    private final AtomicLong eventCount;
    private final AtomicLong errorCount;
    private volatile boolean running;

    public KafkaSecurityEventCollector(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.listeners = new CopyOnWriteArrayList<>();
        this.eventCache = new ConcurrentHashMap<>();
        this.eventCount = new AtomicLong(0);
        this.errorCount = new AtomicLong(0);
        this.running = true;
    }

    @PostConstruct
    public void initialize() {
        log.info("Initializing Kafka Security Event Collector (ZeroTrustSpringEvent unified)");
        log.info("Bootstrap servers: {}", bootstrapServers);
        log.info("Consumer group: {}", groupId);
    }

    @PreDestroy
    public void shutdown() {
        log.info("Shutting down Kafka Security Event Collector");
        running = false;
    }

    // ========== ZeroTrustSpringEvent 수신 ==========

    /**
     * Zero Trust 공통 이벤트 수신
     *
     * AI Native v14.0: 모든 보안 이벤트는 이 리스너로 통일
     *
     * 토픽 패턴: security.events.authorization.*, security.events.authentication.*
     * - security.events.authorization.web
     * - security.events.authorization.method
     * - security.events.authentication.success
     * - security.events.authentication.failure
     */
    @KafkaListener(
        topicPattern = "security\\.events\\.(authorization|authentication)\\..*",
        groupId = "${security.plane.kafka.group-id:security-plane-consumer}",
        containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeZeroTrustEvents(
        @Payload String message,
        @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
        @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
        @Header(KafkaHeaders.OFFSET) long offset,
        Acknowledgment acknowledgment) {
        long startTime = System.currentTimeMillis();
        log.debug("[KafkaCollector] RECEIVED ZeroTrust event from topic '{}' - offset: {}", topic, offset);

        try {
            ZeroTrustSpringEvent zeroTrustEvent = objectMapper.readValue(message, ZeroTrustSpringEvent.class);
            SecurityEvent event = convertZeroTrustToSecurityEvent(zeroTrustEvent);

            event.addMetadata("kafka.topic", topic);
            event.addMetadata("kafka.partition", String.valueOf(partition));
            event.addMetadata("kafka.offset", String.valueOf(offset));
            event.addMetadata("zerotrust.category", zeroTrustEvent.getCategory().name());
            event.addMetadata("zerotrust.eventType", zeroTrustEvent.getEventType());

            processEvent(event);
            eventCount.incrementAndGet();

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[KafkaCollector] PROCESSED ZeroTrust event - topic: {}, category: {}, type: {}, duration: {}ms",
                topic, zeroTrustEvent.getCategory(), zeroTrustEvent.getEventType(), duration);

            if (acknowledgment != null) {
                acknowledgment.acknowledge();
            }

        } catch (Exception e) {
            log.error("[KafkaCollector] ERROR processing ZeroTrust event - topic: {}, offset: {}, error: {}",
                topic, offset, e.getMessage(), e);
            errorCount.incrementAndGet();

            try {
                sendToDeadLetterQueue(message, topic, partition, offset, e);
                if (acknowledgment != null) {
                    acknowledgment.acknowledge();
                }
            } catch (Exception dlqError) {
                log.error("[KafkaCollector] Failed to send to DLQ - offset: {}", offset, dlqError);
            }
        }
    }

    public void registerListener(SecurityEventListener listener) {
        listeners.add(listener);
        log.info("Registered security event listener: {}", listener.getListenerName());
    }

    public void unregisterListener(SecurityEventListener listener) {
        listeners.remove(listener);
        log.info("Unregistered security event listener: {}", listener.getListenerName());
    }

    /**
     * 이벤트 처리 - 즉시 리스너 호출
     */
    private void processEvent(SecurityEvent event) {
        if (event.getEventId() == null) {
            event.setEventId(UUID.randomUUID().toString());
            log.debug("[KafkaCollector] Generated eventId: {}", event.getEventId());
        }

        // Add to cache
        eventCache.put(event.getEventId(), event);

        // Limit cache size
        if (eventCache.size() > 10000) {
            eventCache.entrySet().stream()
                .sorted(Map.Entry.comparingByValue(
                    Comparator.comparing(SecurityEvent::getTimestamp)))
                .limit(1000)
                .map(Map.Entry::getKey)
                .forEach(eventCache::remove);
        }

        // 모든 리스너가 처리 완료된 후에만 상위로 리턴
        if (!listeners.isEmpty()) {
            for (SecurityEventListener listener : listeners) {
                try {
                    log.debug("[KafkaCollector] Calling listener {} for event: {}",
                        listener.getListenerName(), event.getEventId());

                    listener.onSecurityEvent(event);

                    log.debug("[KafkaCollector] Listener {} processed event successfully: {}",
                        listener.getListenerName(), event.getEventId());

                } catch (Exception e) {
                    log.error("[KafkaCollector] Listener {} failed to process event {}: {}",
                        listener.getListenerName(), event.getEventId(), e.getMessage(), e);

                    throw new RuntimeException(
                        String.format("Listener %s failed to process event %s",
                            listener.getListenerName(), event.getEventId()), e);
                }
            }
        }
    }

    /**
     * 통계 조회
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_events", eventCount.get());
        stats.put("error_count", errorCount.get());
        stats.put("cache_size", eventCache.size());
        stats.put("listener_count", listeners.size());
        return stats;
    }

    // ========== 변환 메서드 ==========

    /**
     * ZeroTrustSpringEvent를 SecurityEvent로 변환
     *
     * AI Native v14.0: 모든 이벤트 타입을 ZeroTrustSpringEvent의 payload에서 추출
     */
    private SecurityEvent convertZeroTrustToSecurityEvent(ZeroTrustSpringEvent zeroTrustEvent) {
        Map<String, Object> payload = zeroTrustEvent.getPayload();

        // payload에서 eventId 추출 (없으면 새로 생성)
        String eventId = payload != null && payload.get("eventId") != null
            ? String.valueOf(payload.get("eventId"))
            : UUID.randomUUID().toString();

        // payload에서 userName 추출
        String userName = payload != null && payload.get("userName") != null
            ? String.valueOf(payload.get("userName"))
            : null;

        // payload에서 description 추출 또는 기본값 생성
        String description = payload != null && payload.get("description") != null
            ? String.valueOf(payload.get("description"))
            : zeroTrustEvent.getCategory() + " event: " + zeroTrustEvent.getEventType();

        // payload에서 severity 추출 또는 기본값
        SecurityEvent.Severity severity = determineSeverityFromPayload(payload);

        SecurityEvent event = SecurityEvent.builder()
            .eventId(eventId)
            .source(SecurityEvent.EventSource.IAM)
            .severity(severity)
            .timestamp(LocalDateTime.ofInstant(zeroTrustEvent.getEventTimestamp(), java.time.ZoneId.systemDefault()))
            .description(description)
            .userId(zeroTrustEvent.getUserId())
            .userName(userName)
            .sourceIp(zeroTrustEvent.getClientIp())
            .sessionId(zeroTrustEvent.getSessionId())
            .userAgent(zeroTrustEvent.getUserAgent())
            .build();

        // payload를 메타데이터로 복사
        if (payload != null) {
            payload.forEach((key, value) -> {
                if (value != null && !key.equals("eventId") && !key.equals("userName") && !key.equals("description")) {
                    event.addMetadata(key, String.valueOf(value));
                }
            });
        }

        // 리소스 정보
        if (zeroTrustEvent.getResource() != null) {
            event.addMetadata("requestPath", zeroTrustEvent.getResource());
        }

        return event;
    }

    /**
     * payload에서 severity 결정
     */
    private SecurityEvent.Severity determineSeverityFromPayload(Map<String, Object> payload) {
        if (payload == null) {
            return SecurityEvent.Severity.MEDIUM;
        }

        // 브루트포스 또는 Credential Stuffing 감지 시 HIGH
        Object bruteForce = payload.get("bruteForceDetected");
        Object credentialStuffing = payload.get("credentialStuffingDetected");
        if ((bruteForce != null && Boolean.parseBoolean(String.valueOf(bruteForce))) ||
            (credentialStuffing != null && Boolean.parseBoolean(String.valueOf(credentialStuffing)))) {
            return SecurityEvent.Severity.HIGH;
        }

        // 이상 탐지 시 MEDIUM
        Object anomaly = payload.get("anomalyDetected");
        if (anomaly != null && Boolean.parseBoolean(String.valueOf(anomaly))) {
            return SecurityEvent.Severity.MEDIUM;
        }

        // 인증 실패 시 MEDIUM
        Object failureReason = payload.get("failureReason");
        if (failureReason != null) {
            return SecurityEvent.Severity.MEDIUM;
        }

        // 기본값
        return SecurityEvent.Severity.LOW;
    }

    // ========== DLQ 처리 ==========

    /**
     * Dead Letter Queue로 실패한 메시지 전송
     */
    private void sendToDeadLetterQueue(String message, String topic, int partition, long offset, Exception exception) {
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

            String dlqTopic = topic + "-dlq";
            String dlqJson = objectMapper.writeValueAsString(dlqMessage);

            log.warn("[KafkaCollector] Sending failed message to DLQ - topic: {}, offset: {}", dlqTopic, offset);

        } catch (Exception e) {
            log.error("[KafkaCollector] Failed to serialize DLQ message - offset: {}", offset, e);
            throw new RuntimeException("DLQ send failed", e);
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
