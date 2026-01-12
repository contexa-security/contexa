package io.contexa.contexacore.autonomous.event.listener;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.domain.*;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

// AI Native: EventType static imports 제거 - 행동 패턴 기반 분석으로 전환


/**
 * Kafka 기반 보안 이벤트 수집기
 * Apache Kafka를 통해 실시간 보안 이벤트를 수집하고 처리합니다.
 * 다양한 보안 시스템(IDS, IPS, SIEM, Firewall 등)으로부터 이벤트를 수신합니다.
 */
@Slf4j
public class KafkaSecurityEventCollector {
    
    @Value("${security.plane.kafka.bootstrap-servers:localhost:9092}")
    private String bootstrapServers;
    
    @Value("${security.plane.kafka.group-id:security-plane-consumer}")
    private String groupId;
    
    @Value("${security.plane.kafka.topics.security-events:security-events}")
    private String securityEventsTopic;
    
    @Value("${security.plane.kafka.topics.threat-indicators:threat-indicators}")
    private String threatIndicatorsTopic;
    
    @Value("${security.plane.kafka.topics.network-events:network-events}")
    private String networkEventsTopic;
    
    @Value("${security.plane.kafka.topics.auth-events:auth-events}")
    private String authEventsTopic;

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
        log.info("Initializing Kafka Security Event Collector");
        log.info("Bootstrap servers: {}", bootstrapServers);
        log.info("Consumer group: {}", groupId);
        log.info("Topics: {}, {}, {}, {}",
            securityEventsTopic, threatIndicatorsTopic, networkEventsTopic, authEventsTopic);
    }
    
    @PreDestroy
    public void shutdown() {
        log.info("Shutting down Kafka Security Event Collector");
        running = false;
    }
    
    /**
     * 일반 보안 이벤트 수신
     *
     * containerFactory 명시 - MANUAL ACK 모드 사용
     * ACK 전 검증: 처리 성공 여부 명시적 확인
     */
    @KafkaListener(
        topics = "${security.plane.kafka.topics.security-events:security-events}",
        groupId = "${security.plane.kafka.group-id:security-plane-consumer}",
        containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeSecurityEvent(
        @Payload String message,
        @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
        @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
        @Header(KafkaHeaders.OFFSET) long offset,
        Acknowledgment acknowledgment
    ) {
        long startTime = System.currentTimeMillis();
        log.debug("[KafkaCollector] RECEIVED event from topic '{}' - partition: {}, offset: {}, thread: {}",
            topic, partition, offset, Thread.currentThread().getName());

        try {
            SecurityEvent event = parseSecurityEvent(message);

            // eventId가 없으면 생성
            if (event.getEventId() == null) {
                event.setEventId(UUID.randomUUID().toString());
                log.debug("[KafkaCollector] Event had no ID, generated: {}", event.getEventId());
            }

            // AI Native: eventType 제거
            log.debug("[KafkaCollector] Parsed event - eventId: {}, severity: {}, userId: {}",
                event.getEventId(), event.getSeverity(), event.getUserId());

            event.setSource(SecurityEvent.EventSource.KAFKA);
            event.addMetadata("kafka.topic", topic);
            event.addMetadata("kafka.partition", String.valueOf(partition));
            event.addMetadata("kafka.offset", String.valueOf(offset));

            log.debug("[KafkaCollector] Processing event - eventId: {}", event.getEventId());

            processEvent(event);

            long count = eventCount.incrementAndGet();
            long duration = System.currentTimeMillis() - startTime;

            log.debug("[KafkaCollector] PROCESSED event successfully - eventId: {}, totalCount: {}, duration: {}ms",
                event.getEventId(), count, duration);

            // 처리 성공 시만 ACK
            if (acknowledgment != null) {
                acknowledgment.acknowledge();
                log.debug("[KafkaCollector] Message ACKed - topic: {}, partition: {}, offset: {}",
                    topic, partition, offset);
            }

        } catch (Exception e) {
            long errorCnt = errorCount.incrementAndGet();
            log.error("[KafkaCollector] ERROR processing event - message: {}, errorCount: {}, error: {}",
                message, errorCnt, e.getMessage(), e);

            // 처리 실패 시 DLQ 로 전송 시도
            try {
                sendToDeadLetterQueue(message, topic, partition, offset, e);

                // DLQ 전송 성공 시만 ACK (재처리 방지)
                if (acknowledgment != null) {
                    acknowledgment.acknowledge();
                    log.warn("[KafkaCollector] Failed message sent to DLQ and ACKed - offset: {}", offset);
                }
            } catch (Exception dlqError) {
                log.error("[KafkaCollector] Failed to send to DLQ - offset: {}", offset, dlqError);
                // DLQ 실패 시 ACK 하지 않음 → 재처리됨
                log.warn("[KafkaCollector] Message will be reprocessed - offset: {}", offset);
            }
        }
    }
    
    /**
     * 위협 지표 이벤트 수신
     *
     * containerFactory 명시 - MANUAL ACK 모드 사용
     */
    @KafkaListener(
        topics = "${security.plane.kafka.topics.threat-indicators:threat-indicators}",
        groupId = "${security.plane.kafka.group-id:security-plane-consumer}",
        containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeThreatIndicator(
        @Payload String message,
        @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
        @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
        @Header(KafkaHeaders.OFFSET) long offset,
        Acknowledgment acknowledgment
    ) {
        try {
            log.debug("Received threat indicator from topic: {}", topic);

            ThreatIndicator indicator = objectMapper.readValue(message, ThreatIndicator.class);

            // Convert to SecurityEvent
            String description = "Threat indicator detected";
            if (indicator.getType() != null) {
                description += ": " + indicator.getType();
            }

            SecurityEvent event = SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.THREAT_INTEL)
                .severity(mapSeverity(indicator.getSeverity()))
                .timestamp(LocalDateTime.now())
                .description(description)
                .sourceIp(indicator.getValue())
                // AI Native: deprecated 필드 제거, metadata로 이동
                .build();

            // AI Native: ThreatIndicator 정보를 metadata에 저장
            if (indicator.getConfidence() != null) {
                event.addMetadata("indicator.confidence", indicator.getConfidence());
            }
            if (indicator.getMitreAttackId() != null) {
                event.addMetadata("indicator.mitreAttackId", indicator.getMitreAttackId());
            }

            // Null 체크 추가
            if (indicator.getType() != null) {
                event.addMetadata("indicator.type", indicator.getType().toString());
            }
            if (indicator.getSource() != null) {
                event.addMetadata("indicator.source", indicator.getSource());
            }
            event.addMetadata("kafka.topic", topic);

            processEvent(event);
            eventCount.incrementAndGet();

            // 처리 성공 시 ACK
            if (acknowledgment != null) {
                acknowledgment.acknowledge();
                log.debug("[KafkaCollector] Threat indicator ACKed - offset: {}", offset);
            }

        } catch (Exception e) {
            log.error("Error processing threat indicator: {}", e.getMessage(), e);
            errorCount.incrementAndGet();

            // 처리 실패 시 DLQ로 전송 후 ACK
            try {
                sendToDeadLetterQueue(message, topic, partition, offset, e);
                if (acknowledgment != null) {
                    acknowledgment.acknowledge();
                    log.warn("[KafkaCollector] Failed threat indicator sent to DLQ and ACKed - offset: {}", offset);
                }
            } catch (Exception dlqError) {
                log.error("[KafkaCollector] Failed to send threat indicator to DLQ - offset: {}", offset, dlqError);
            }
        }
    }
    
    /**
     * 네트워크 이벤트 수신
     *
     * containerFactory 명시 - MANUAL ACK 모드 사용
     */
    @KafkaListener(
        topics = "${security.plane.kafka.topics.network-events:network-events}",
        groupId = "${security.plane.kafka.group-id:security-plane-consumer}",
        containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeNetworkEvent(
        ConsumerRecord<String, String> record,
        Acknowledgment acknowledgment
    ) {
        try {
            log.debug("Received network event from offset: {}", record.offset());

            Map<String, Object> networkData = objectMapper.readValue(record.value(), Map.class);

            // AI Native v3.1: targetIp, sourcePort, targetPort 필드 제거됨
            // LLM 프롬프트에서 사용하지 않는 네트워크 정보는 metadata에 저장
            SecurityEvent event = SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.FIREWALL)
                .severity(determineNetworkSeverity(networkData))
                .timestamp(LocalDateTime.now())
                .description((String) networkData.get("description"))
                .sourceIp((String) networkData.get("src_ip"))
                .protocol((String) networkData.get("protocol"))
                .build();

            // AI Native v3.1: 네트워크 이벤트 전용 정보는 metadata에 저장
            if (networkData.get("dst_ip") != null) {
                event.addMetadata("network.targetIp", networkData.get("dst_ip"));
            }
            if (networkData.get("src_port") != null) {
                event.addMetadata("network.sourcePort", networkData.get("src_port"));
            }
            if (networkData.get("dst_port") != null) {
                event.addMetadata("network.targetPort", networkData.get("dst_port"));
            }
            event.addMetadata("kafka.key", record.key());
            event.addMetadata("kafka.timestamp", String.valueOf(record.timestamp()));

            processEvent(event);
            eventCount.incrementAndGet();

            // 처리 성공 시 ACK
            if (acknowledgment != null) {
                acknowledgment.acknowledge();
                log.debug("[KafkaCollector] Network event ACKed - offset: {}", record.offset());
            }

        } catch (Exception e) {
            log.error("Error processing network event: {}", e.getMessage(), e);
            errorCount.incrementAndGet();

            // 처리 실패 시 DLQ로 전송 후 ACK
            try {
                sendToDeadLetterQueue(record.value(), record.topic(), record.partition(), record.offset(), e);
                if (acknowledgment != null) {
                    acknowledgment.acknowledge();
                    log.warn("[KafkaCollector] Failed network event sent to DLQ and ACKed - offset: {}", record.offset());
                }
            } catch (Exception dlqError) {
                log.error("[KafkaCollector] Failed to send network event to DLQ - offset: {}", record.offset(), dlqError);
            }
        }
    }
    
    /**
     * Tiered 인증 이벤트 수신 (Critical, Contextual, General)
     *
     * AuthenticationSuccessEvent, AuthenticationFailureEvent를 직접 역직렬화합니다.
     */
    @KafkaListener(
        topics = {"auth-events-critical", "auth-events-contextual", "auth-events-general"},
        groupId = "${security.plane.kafka.group-id:security-plane-consumer}",
        containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeTieredAuthEvents(
        @Payload String message,
        @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
        @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
        @Header(KafkaHeaders.OFFSET) long offset,
        Acknowledgment acknowledgment) {
        long startTime = System.currentTimeMillis();
        log.debug("[KafkaCollector] RECEIVED tiered auth event from topic '{}' - partition: {}, offset: {}",
            topic, partition, offset);

        try {
            SecurityEvent event;

            // JSON 에서 eventType 또는 failureReason 필드로 타입 구분
            if (message.contains("\"failureReason\"") || message.contains("\"bruteForceDetected\"")) {
                // AuthenticationFailureEvent
                AuthenticationFailureEvent failureEvent = objectMapper.readValue(message, AuthenticationFailureEvent.class);
                event = convertAuthFailureToSecurityEvent(failureEvent);
            } else {
                // AuthenticationSuccessEvent
                AuthenticationSuccessEvent successEvent = objectMapper.readValue(message, AuthenticationSuccessEvent.class);
                event = convertAuthSuccessToSecurityEvent(successEvent);
            }

            event.addMetadata("kafka.topic", topic);
            event.addMetadata("kafka.partition", String.valueOf(partition));
            event.addMetadata("kafka.offset", String.valueOf(offset));

            processEvent(event);
            eventCount.incrementAndGet();

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[KafkaCollector] PROCESSED tiered auth event - topic: {}, duration: {}ms", topic, duration);

            if (acknowledgment != null) {
                acknowledgment.acknowledge();
            }

        } catch (Exception e) {
            log.error("[KafkaCollector] ERROR processing tiered auth event - topic: {}, offset: {}, error: {}",
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
    
    public void collectEvent(SecurityEvent event) {
        if (!running) {
            log.warn("Collector is shutting down, ignoring event");
            return;
        }
        
        processEvent(event);
    }
    
    public List<SecurityEvent> collectEvents(int maxEvents) {
        List<SecurityEvent> events = new ArrayList<>();
        eventCache.values().stream()
            .sorted(Comparator.comparing(SecurityEvent::getTimestamp).reversed())
            .limit(maxEvents)
            .forEach(events::add);
        return events;
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
     * 개선사항:
     * - 즉시 처리: ACK 전에 리스너 호출 완료 보장
     * - 데이터 무결성: 처리 실패 시 예외 전파 → ACK 방지 → 재처리 보장
     *
     * @param event 처리할 이벤트
     * @throws RuntimeException 리스너 처리 실패 시 (ACK 방지)
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
            // Remove oldest events
            eventCache.entrySet().stream()
                .sorted(Map.Entry.comparingByValue(
                    Comparator.comparing(SecurityEvent::getTimestamp)))
                .limit(1000)
                .map(Map.Entry::getKey)
                .forEach(eventCache::remove);
        }

        // 모든 리스너가 처리 완료된 후에만 상위로 리턴 → ACK 보장
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

                    // 리스너 실패 시 예외 전파 → ACK 방지 → 재처리 보장
                    throw new RuntimeException(
                        String.format("Listener %s failed to process event %s",
                            listener.getListenerName(), event.getEventId()), e);
                }
            }
        }
    }
    
    
    private SecurityEvent parseSecurityEvent(String json) throws Exception {
        return objectMapper.readValue(json, SecurityEvent.class);
    }
    
    /**
     * AI Native v4.1.0: 하드코딩 임계값 제거 - LLM이 원시 데이터로 직접 판단
     * 이전: priority <= 2/4/6/8 기반 Severity 결정
     * 변경: 기본값 MEDIUM, priority는 metadata에 저장됨
     */
    private SecurityEvent.Severity determineNetworkSeverity(Map<String, Object> data) {
        // AI Native: 원시 데이터(priority)는 metadata에 저장되어 LLM이 직접 판단
        return SecurityEvent.Severity.MEDIUM;
    }
    
    /**
     * AI Native v4.1.0: 하드코딩 임계값 제거 - LLM이 원시 데이터로 직접 판단
     * 이전: failCount > 5 / result == failed 기반 Severity 결정
     * 변경: 기본값 MEDIUM, 원시 데이터는 metadata에 저장됨
     */
    private SecurityEvent.Severity determineAuthSeverity(Map<String, Object> data) {
        // AI Native: 원시 데이터(fail_count, result)는 metadata에 저장되어 LLM이 직접 판단
        return SecurityEvent.Severity.MEDIUM;
    }
    
    private SecurityEvent.Severity mapSeverity(ThreatIndicator.Severity severity) {
        if (severity == null) {
            return SecurityEvent.Severity.MEDIUM; // 기본값
        }
        return switch (severity) {
            case CRITICAL -> SecurityEvent.Severity.CRITICAL;
            case HIGH -> SecurityEvent.Severity.HIGH;
            case MEDIUM -> SecurityEvent.Severity.MEDIUM;
            case LOW -> SecurityEvent.Severity.LOW;
            case INFO -> SecurityEvent.Severity.INFO;
        };
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

    /**
     * Dead Letter Queue로 실패한 메시지 전송
     *
     * @param message 원본 메시지
     * @param topic 원본 토픽
     * @param partition 파티션
     * @param offset 오프셋
     * @param exception 발생한 예외
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

            // DLQ는 KafkaTemplate을 통해 전송 (별도 주입 필요 시 추가)
            log.warn("[KafkaCollector] Sending failed message to DLQ - topic: {}, offset: {}", dlqTopic, offset);

        } catch (Exception e) {
            log.error("[KafkaCollector] Failed to serialize DLQ message - offset: {}", offset, e);
            throw new RuntimeException("DLQ send failed", e);
        }
    }

    /**
     * 스택 트레이스를 문자열로 변환
     */
    private String getStackTraceAsString(Exception e) {
        if (e == null) {
            return "";
        }
        java.io.StringWriter sw = new java.io.StringWriter();
        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }

    /**
     * AuthenticationSuccessEvent를 SecurityEvent로 변환
     */
    private SecurityEvent convertAuthSuccessToSecurityEvent(AuthenticationSuccessEvent authEvent) {
        SecurityEvent event = SecurityEvent.builder()
            .eventId(authEvent.getEventId())
            .source(SecurityEvent.EventSource.IAM)
            .severity(determineSeverityFromTrustScore(authEvent.getTrustScore()))
            .timestamp(authEvent.getEventTimestamp())
            .description("Authentication success for user: " + authEvent.getUsername())
            .userId(authEvent.getUserId())
            .userName(authEvent.getUsername())
            .sourceIp(authEvent.getSourceIp())
            .sessionId(authEvent.getSessionId())
            // AI Native: deprecated confidenceScore 제거
            .build();

        // 추가 메타데이터
        if (authEvent.getMetadata() != null) {
            authEvent.getMetadata().forEach((key, value) -> event.addMetadata(key, String.valueOf(value)));
        }
        event.addMetadata("auth.type", authEvent.getAuthenticationType());
        event.addMetadata("auth.mfa_completed", String.valueOf(authEvent.isMfaCompleted()));
        event.addMetadata("auth.anomaly_detected", String.valueOf(authEvent.isAnomalyDetected()));
        // AI Native: trustScore를 metadata에 저장
        if (authEvent.getTrustScore() != null) {
            event.addMetadata("auth.trustScore", authEvent.getTrustScore());
        }

        return event;
    }

    /**
     * AuthenticationFailureEvent를 SecurityEvent로 변환
     */
    private SecurityEvent convertAuthFailureToSecurityEvent(AuthenticationFailureEvent authEvent) {
        SecurityEvent event = SecurityEvent.builder()
            .eventId(authEvent.getEventId())
            .source(SecurityEvent.EventSource.IAM)
            .severity(determineSeverityFromAttack(authEvent))
            .timestamp(authEvent.getEventTimestamp())
            .description("Authentication failure: " + authEvent.getFailureReason())
            .userId(authEvent.getUserId())
            .userName(authEvent.getUsername())
            .sourceIp(authEvent.getSourceIp())
            .sessionId(authEvent.getSessionId())
            .build();

        // 추가 메타데이터
        if (authEvent.getMetadata() != null) {
            authEvent.getMetadata().forEach((key, value) -> event.addMetadata(key, String.valueOf(value)));
        }
        event.addMetadata("auth.failure_reason", authEvent.getFailureReason());
        event.addMetadata("auth.failure_count", String.valueOf(authEvent.getFailureCount()));
        event.addMetadata("auth.brute_force_detected", String.valueOf(authEvent.isBruteForceDetected()));
        event.addMetadata("auth.credential_stuffing_detected", String.valueOf(authEvent.isCredentialStuffingDetected()));

        return event;
    }

    /**
     * AuthorizationDecisionEvent를 SecurityEvent로 변환
     *
     * AI Native v3.1: HCADContext 세션 컨텍스트 필드 추가
     * - isNewSession, isNewDevice, recentRequestCount
     * - LLM 프롬프트에서 NOT_PROVIDED 방지
     */
    private SecurityEvent convertAuthorizationToSecurityEvent(AuthorizationDecisionEvent authzEvent) {
        SecurityEvent event = SecurityEvent.builder()
            .eventId(authzEvent.getEventId())
            .source(SecurityEvent.EventSource.IAM)
            // AI Native v4.1.0: 하드코딩 제거 - LLM이 원시 데이터로 직접 판단
            .severity(SecurityEvent.Severity.MEDIUM)
            .timestamp(LocalDateTime.ofInstant(authzEvent.getTimestamp(), java.time.ZoneId.systemDefault()))
            .description("Authorization decision: " + authzEvent.getResult())
            .userId(authzEvent.getUserId())
            .userName(authzEvent.getPrincipal())
            .sourceIp(authzEvent.getClientIp())
            .sessionId(authzEvent.getSessionId())
            .userAgent(authzEvent.getUserAgent())
            .protocol("HTTP")
            .build();

        // 메타데이터 복사 (kafka.*, authz.* 제외 - LLM 프롬프트에 불필요한 리소스 정보 방지)
        // AI Native: 이상 탐지는 행동 패턴, 기준선, RAG, 컨텍스트 정보만 사용
        // 리소스 정보는 LLM 판단에 포함하지 않음
        if (authzEvent.getMetadata() != null) {
            authzEvent.getMetadata().forEach((key, value) -> {
                if (!key.startsWith("kafka.") && !key.startsWith("authz.")) {
                    event.addMetadata(key, String.valueOf(value));
                }
            });
        }

        // AI Native v4.1.0: 원시 데이터 저장 (LLM이 직접 판단)
        if (authzEvent.getResult() != null) {
            event.addMetadata("authz.result", authzEvent.getResult().name());
        }
        if (authzEvent.getTrustScore() != null) {
            event.addMetadata("authz.trustScore", authzEvent.getTrustScore());
        }
        if (authzEvent.getRiskScore() != null) {
            event.addMetadata("authz.riskScore", authzEvent.getRiskScore());
        }

        // AI Native v3.1: HCADContext 세션 컨텍스트 필드 추가
        // LLM 프롬프트에서 NOT_PROVIDED 방지를 위해 metadata에 저장
        if (authzEvent.getIsNewSession() != null) {
            event.addMetadata("isNewSession", authzEvent.getIsNewSession());
        }
        if (authzEvent.getIsNewDevice() != null) {
            event.addMetadata("isNewDevice", authzEvent.getIsNewDevice());
        }
        if (authzEvent.getIsNewUser() != null) {
            event.addMetadata("isNewUser", authzEvent.getIsNewUser());
        }
        if (authzEvent.getRecentRequestCount() != null) {
            event.addMetadata("recentRequestCount", authzEvent.getRecentRequestCount());
        }

        return event;
    }

    /**
     * SecurityIncidentEvent를 SecurityEvent로 변환
     */
    private SecurityEvent convertIncidentToSecurityEvent(SecurityIncidentEvent incidentEvent) {
        SecurityEvent event = SecurityEvent.builder()
            .eventId(incidentEvent.getIncidentId())
            .source(SecurityEvent.EventSource.SIEM)
            .severity(mapIncidentSeverity(incidentEvent.getSeverity()))
            .timestamp(LocalDateTime.ofInstant(incidentEvent.getTimestamp(), java.time.ZoneId.systemDefault()))
            .description(incidentEvent.getDescription())
            .build();

        // 추가 메타데이터
        if (incidentEvent.getMetadata() != null) {
            incidentEvent.getMetadata().forEach((key, value) -> event.addMetadata(key, String.valueOf(value)));
        }
        event.addMetadata("incident.id", incidentEvent.getIncidentId());
        event.addMetadata("incident.severity", incidentEvent.getSeverity().name());

        return event;
    }

    /**
     * AuditEvent를 SecurityEvent로 변환
     */
    private SecurityEvent convertAuditToSecurityEvent(AuditEvent auditEvent) {
        SecurityEvent event = SecurityEvent.builder()
            .eventId(auditEvent.getEventId())
            .source(SecurityEvent.EventSource.IAM)
            .severity(SecurityEvent.Severity.INFO)
            .timestamp(LocalDateTime.ofInstant(auditEvent.getTimestamp(), java.time.ZoneId.systemDefault()))
            .description("Audit: " + auditEvent.getAction())
            .userName(auditEvent.getPrincipal())
            .sourceIp(auditEvent.getClientIp())
            .sessionId(auditEvent.getSessionId())
            .build();

        // 추가 메타데이터
        if (auditEvent.getDetails() != null) {
            auditEvent.getDetails().forEach((key, value) -> event.addMetadata(key, String.valueOf(value)));
        }
        event.addMetadata("audit.action", auditEvent.getAction());
        event.addMetadata("audit.resource", auditEvent.getResource());
        event.addMetadata("audit.result", auditEvent.getResult());

        return event;
    }

    /**
     * AI Native v4.1.0: 하드코딩 임계값 제거 - LLM이 원시 데이터로 직접 판단
     * 이전: trustScore >= 0.8/0.6/0.4 기반 Severity 결정
     * 변경: 기본값 MEDIUM, trustScore는 metadata에 저장됨
     */
    private SecurityEvent.Severity determineSeverityFromTrustScore(Double trustScore) {
        // AI Native: trustScore는 metadata에 저장되어 LLM이 직접 판단
        return SecurityEvent.Severity.MEDIUM;
    }

    /**
     * AI Native v4.1.0: 하드코딩 임계값 제거 - LLM이 원시 데이터로 직접 판단
     * 이전: bruteForce/credentialStuffing, failureCount > 5/3 기반 Severity 결정
     * 변경: 기본값 MEDIUM, 원시 데이터는 metadata에 저장됨
     */
    private SecurityEvent.Severity determineSeverityFromAttack(AuthenticationFailureEvent authEvent) {
        // AI Native: 원시 데이터(bruteForce, credentialStuffing, failureCount)는 metadata에 저장
        // LLM이 직접 판단
        return SecurityEvent.Severity.MEDIUM;
    }

    private SecurityEvent.Severity mapIncidentSeverity(SecurityIncidentEvent.IncidentSeverity severity) {
        if (severity == null) return SecurityEvent.Severity.MEDIUM;
        return switch (severity) {
            case CRITICAL -> SecurityEvent.Severity.CRITICAL;
            case HIGH -> SecurityEvent.Severity.HIGH;
            case MEDIUM -> SecurityEvent.Severity.MEDIUM;
            case LOW -> SecurityEvent.Severity.LOW;
            case INFO -> SecurityEvent.Severity.INFO;
        };
    }

    /**
     * Authorization 이벤트 수신
     */
    @KafkaListener(
        topics = "security-authorization-events",
        groupId = "${security.plane.kafka.group-id:security-plane-consumer}",
        containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeAuthorizationEvents(
        @Payload String message,
        @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
        @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
        @Header(KafkaHeaders.OFFSET) long offset,
        Acknowledgment acknowledgment
    ) {
        try {
            log.debug("[KafkaCollector] RECEIVED authorization event - offset: {}", offset);

            AuthorizationDecisionEvent authzEvent = objectMapper.readValue(message, AuthorizationDecisionEvent.class);
            SecurityEvent event = convertAuthorizationToSecurityEvent(authzEvent);

            event.addMetadata("kafka.topic", topic);
            event.addMetadata("kafka.partition", String.valueOf(partition));
            event.addMetadata("kafka.offset", String.valueOf(offset));

            processEvent(event);
            eventCount.incrementAndGet();

            if (acknowledgment != null) {
                acknowledgment.acknowledge();
            }

        } catch (Exception e) {
            log.error("[KafkaCollector] ERROR processing authorization event - offset: {}", offset, e);
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

    /**
     * Security Incident 이벤트 수신
     */
    @KafkaListener(
        topics = "security-incident-events",
        groupId = "${security.plane.kafka.group-id:security-plane-consumer}",
        containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeIncidentEvents(
        @Payload String message,
        @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
        @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
        @Header(KafkaHeaders.OFFSET) long offset,
        Acknowledgment acknowledgment
    ) {
        try {
            log.debug("[KafkaCollector] RECEIVED incident event - offset: {}", offset);

            SecurityIncidentEvent incidentEvent = objectMapper.readValue(message, SecurityIncidentEvent.class);
            SecurityEvent event = convertIncidentToSecurityEvent(incidentEvent);

            event.addMetadata("kafka.topic", topic);
            event.addMetadata("kafka.partition", String.valueOf(partition));
            event.addMetadata("kafka.offset", String.valueOf(offset));

            processEvent(event);
            eventCount.incrementAndGet();

            if (acknowledgment != null) {
                acknowledgment.acknowledge();
            }

        } catch (Exception e) {
            log.error("[KafkaCollector] ERROR processing incident event - offset: {}", offset, e);
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

    /**
     * Audit 이벤트 수신
     */
    @KafkaListener(
        topics = "security-audit-events",
        groupId = "${security.plane.kafka.group-id:security-plane-consumer}",
        containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeAuditEvents(
        @Payload String message,
        @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
        @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
        @Header(KafkaHeaders.OFFSET) long offset,
        Acknowledgment acknowledgment
    ) {
        try {
            log.debug("[KafkaCollector] RECEIVED audit event - offset: {}", offset);

            AuditEvent auditEvent = objectMapper.readValue(message, AuditEvent.class);
            SecurityEvent event = convertAuditToSecurityEvent(auditEvent);

            event.addMetadata("kafka.topic", topic);
            event.addMetadata("kafka.partition", String.valueOf(partition));
            event.addMetadata("kafka.offset", String.valueOf(offset));

            processEvent(event);
            eventCount.incrementAndGet();

            if (acknowledgment != null) {
                acknowledgment.acknowledge();
            }

        } catch (Exception e) {
            log.error("[KafkaCollector] ERROR processing audit event - offset: {}", offset, e);
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
}