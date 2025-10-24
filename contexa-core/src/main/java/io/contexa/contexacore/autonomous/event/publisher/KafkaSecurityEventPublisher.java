package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.autonomous.event.domain.SecurityIncidentEvent;
import io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent;
import io.contexa.contexacore.autonomous.event.domain.AuditEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.TieredEventProcessor;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

/**
 * Kafka 기반 보안 이벤트 발행자
 * 
 * 모든 보안 이벤트를 Kafka로 발행하여 영구 저장 및 분산 처리를 지원합니다.
 * 실패 시 Dead Letter Queue로 전송하여 이벤트 손실을 방지합니다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class KafkaSecurityEventPublisher implements SecurityEventPublisher {
    
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final ObjectMapper objectMapper;
    private final TieredEventProcessor tieredEventProcessor;
    
    @Value("${security.kafka.topic.authorization:security-authorization-events}")
    private String authorizationTopic;

    @Value("${security.kafka.topic.authentication:auth-events}")
    private String authenticationTopic;

    @Value("${security.kafka.topic.incident:security-incident-events}")
    private String incidentTopic;

    @Value("${security.kafka.topic.threat:threat-indicators}")
    private String threatTopic;

    @Value("${security.kafka.topic.audit:security-audit-events}")
    private String auditTopic;

    @Value("${security.kafka.topic.general:security-events}")
    private String generalTopic;

    @Value("${security.kafka.topic.dlq:security-events-dlq}")
    private String deadLetterTopic;
    
    @Override
    public void publishAuthorizationEvent(AuthorizationDecisionEvent event) {
        try {
            String key = generateKey(event.getPrincipal(), event.getSessionId());
            
            CompletableFuture<SendResult<String, Object>> future = 
                kafkaTemplate.send(authorizationTopic, key, event);
                
            future.whenComplete((result, ex) -> {
                if (ex == null) {
                    log.debug("Authorization event published to Kafka: eventId={}, principal={}, result={}", 
                        event.getEventId(), event.getPrincipal(), event.getResult());
                } else {
                    log.error("Failed to publish authorization event to Kafka: eventId={}", 
                        event.getEventId(), ex);
                    sendToDeadLetterQueue(event, ex);
                }
            });
        } catch (Exception e) {
            log.error("Error publishing authorization event: eventId={}", event.getEventId(), e);
            sendToDeadLetterQueue(event, e);
        }
    }
    
    @Override
    public void publishSecurityIncident(SecurityIncidentEvent event) {
        try {
            String key = event.getIncidentId();
            
            CompletableFuture<SendResult<String, Object>> future = 
                kafkaTemplate.send(incidentTopic, key, event);
                
            future.whenComplete((result, ex) -> {
                if (ex == null) {
                    log.info("Security incident published to Kafka: incidentId={}, severity={}", 
                        event.getIncidentId(), event.getSeverity());
                } else {
                    log.error("Failed to publish security incident to Kafka: incidentId={}", 
                        event.getIncidentId(), ex);
                    sendToDeadLetterQueue(event, ex);
                }
            });
        } catch (Exception e) {
            log.error("Error publishing security incident: incidentId={}", event.getIncidentId(), e);
            sendToDeadLetterQueue(event, e);
        }
    }
    
    @Override
    public void publishThreatDetection(ThreatDetectionEvent event) {
        try {
            String key = event.getThreatId();
            
            CompletableFuture<SendResult<String, Object>> future = 
                kafkaTemplate.send(threatTopic, key, event);
                
            future.whenComplete((result, ex) -> {
                if (ex == null) {
                    log.info("Threat detection event published to Kafka: threatId={}, level={}, confidence={}", 
                        event.getThreatId(), event.getThreatLevel(), event.getConfidenceScore());
                } else {
                    log.error("Failed to publish threat detection to Kafka: threatId={}", 
                        event.getThreatId(), ex);
                    sendToDeadLetterQueue(event, ex);
                }
            });
        } catch (Exception e) {
            log.error("Error publishing threat detection: threatId={}", event.getThreatId(), e);
            sendToDeadLetterQueue(event, e);
        }
    }
    
    @Override
    public void publishAuditEvent(AuditEvent event) {
        try {
            String key = generateKey(event.getPrincipal(), event.getSessionId());
            
            CompletableFuture<SendResult<String, Object>> future = 
                kafkaTemplate.send(auditTopic, key, event);
                
            future.whenComplete((result, ex) -> {
                if (ex == null) {
                    log.trace("Audit event published to Kafka: eventId={}, principal={}, action={}", 
                        event.getEventId(), event.getPrincipal(), event.getAction());
                } else {
                    log.error("Failed to publish audit event to Kafka: eventId={}", 
                        event.getEventId(), ex);
                    sendToDeadLetterQueue(event, ex);
                }
            });
        } catch (Exception e) {
            log.error("Error publishing audit event: eventId={}", event.getEventId(), e);
            sendToDeadLetterQueue(event, e);
        }
    }
    
    @Override
    public void publishAuthenticationSuccess(AuthenticationSuccessEvent event) {
        try {
            // 계층 결정 - Zero Trust를 위해 모든 성공 인증을 분석
            TieredEventProcessor.EventTier tier = tieredEventProcessor.determineTier(event);

            String key = generateKey(event.getUsername(), event.getSessionId());
            String topic = determineTopic(tier, authenticationTopic);

            // 모든 계층 비동기 처리 (일관된 처리 전략)
            // 순수 DTO이므로 직접 발행 가능
            CompletableFuture<SendResult<String, Object>> future =
                kafkaTemplate.send(topic, key, event);

            future.whenComplete((result, ex) -> {
                if (ex == null) {
                    // 계층별 로그 레벨 차등화
                    if (tier == TieredEventProcessor.EventTier.CRITICAL) {
                        log.warn("CRITICAL authentication success published: eventId={}, user={}, riskLevel={}, topic={}",
                            event.getEventId(), event.getUsername(), event.calculateRiskLevel(), topic);
                    } else {
                        log.debug("Authentication success published: eventId={}, user={}, tier={}, topic={}",
                            event.getEventId(), event.getUsername(), tier, topic);
                    }
                } else {
                    log.error("Failed to publish authentication success: eventId={}, tier={}",
                        event.getEventId(), tier, ex);
                    sendToDeadLetterQueue(event, ex);
                }
            });
        } catch (Exception e) {
            log.error("Error publishing authentication success: eventId={}", event.getEventId(), e);
            sendToDeadLetterQueue(event, e);
        }
    }
    
    @Override
    public void publishAuthenticationFailure(AuthenticationFailureEvent event) {
        try {
            // 계층 결정 - 공격 패턴 감지
            TieredEventProcessor.EventTier tier = tieredEventProcessor.determineTier(event);

            String key = generateKey(event.getUsername(), event.getSessionId());
            String topic = determineTopic(tier, authenticationTopic);

            // 모든 계층 비동기 처리 (일관된 처리 전략)
            // 순수 DTO이므로 직접 발행 가능
            CompletableFuture<SendResult<String, Object>> future =
                kafkaTemplate.send(topic, key, event);

            future.whenComplete((result, ex) -> {
                if (ex == null) {
                    // 계층별 로그 레벨 차등화
                    if (tier == TieredEventProcessor.EventTier.CRITICAL) {
                        log.warn("CRITICAL authentication failure published: eventId={}, user={}, attackType={}, topic={}",
                            event.getEventId(), event.getUsername(), event.determineAttackType(), topic);
                    } else {
                        log.debug("Authentication failure published: eventId={}, user={}, tier={}, topic={}",
                            event.getEventId(), event.getUsername(), tier, topic);
                    }
                } else {
                    log.error("Failed to publish authentication failure: eventId={}, tier={}",
                        event.getEventId(), tier, ex);
                    sendToDeadLetterQueue(event, ex);
                }
            });
        } catch (Exception e) {
            log.error("Error publishing authentication failure: eventId={}", event.getEventId(), e);
            sendToDeadLetterQueue(event, e);
        }
    }
    
    @Override
    public void publishSecurityEvent(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        log.debug("[KafkaPublisher] START publishing event - eventId={}, type={}, thread={}",
            event.getEventId(), event.getEventType(), Thread.currentThread().getName());

        try {
            String key = event.getEventId();
            String topic = generalTopic;

            log.debug("[KafkaPublisher] Sending to Kafka topic '{}' - eventId={}",
                topic, event.getEventId());

            CompletableFuture<SendResult<String, Object>> future =
                kafkaTemplate.send(topic, key, event);

            future.whenComplete((result, ex) -> {
                long duration = System.currentTimeMillis() - startTime;
                if (ex == null) {
                    log.debug("[KafkaPublisher] SUCCESS - Event published to topic '{}' - eventId={}, type={}, duration={}ms",
                        topic, event.getEventId(), event.getEventType(), duration);
                } else {
                    log.error("[KafkaPublisher] FAILED to publish event - eventId={}, error: {}, duration={}ms",
                        event.getEventId(), ex.getMessage(), duration, ex);
                    sendToDeadLetterQueue(event, ex);
                }
            });

            log.debug("[KafkaPublisher] Kafka send initiated for eventId={}", event.getEventId());

        } catch (Exception e) {
            log.error("[KafkaPublisher] ERROR during publishing - eventId={}, error: {}",
                event.getEventId(), e.getMessage(), e);
            sendToDeadLetterQueue(event, e);
        }
    }
    
    /**
     * 계층별 토픽 결정
     */
    private String determineTopic(TieredEventProcessor.EventTier tier, String baseTopic) {
        switch (tier) {
            case CRITICAL:
                return baseTopic + "-critical";
            case CONTEXTUAL:
                return baseTopic + "-contextual";
            case GENERAL:
                return baseTopic + "-general";
            default:
                return baseTopic;
        }
    }
    
    /**
     * Dead Letter Queue로 실패한 이벤트 전송
     */
    private void sendToDeadLetterQueue(Object event, Throwable exception) {
        try {
            DeadLetterEvent dlqEvent = DeadLetterEvent.builder()
                .originalEvent(event)
                .errorMessage(exception.getMessage())
                .errorType(exception.getClass().getName())
                .build();
            
            kafkaTemplate.send(deadLetterTopic, dlqEvent);
            log.warn("Event sent to Dead Letter Queue: {}", event);
        } catch (Exception e) {
            log.error("Failed to send event to Dead Letter Queue", e);
        }
    }
    
    /**
     * Kafka 메시지 키 생성
     */
    private String generateKey(String principal, String sessionId) {
        if (sessionId != null && !sessionId.isEmpty()) {
            return sessionId;
        }
        if (principal != null && !principal.isEmpty()) {
            return principal;
        }
        return "unknown";
    }
    
    /**
     * Dead Letter Event 내부 클래스
     */
    @lombok.Data
    @lombok.Builder
    private static class DeadLetterEvent {
        private Object originalEvent;
        private String errorMessage;
        private String errorType;
        @lombok.Builder.Default
        private long timestamp = System.currentTimeMillis();
    }
}