package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.autonomous.event.domain.SecurityIncidentEvent;
import io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent;
import io.contexa.contexacore.autonomous.event.domain.AuditEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * 복합 보안 이벤트 발행자
 *
 * Kafka와 Redis를 순차적으로 사용하여 이벤트를 발행합니다.
 * - Kafka: 영구 저장 및 순차 처리를 위한 이벤트 스트림
 * - Redis: 실시간 전파 및 빠른 접근을 위한 캐시
 *
 * AI Native v6.0: CompletableFuture 제거 - 순차 실행
 * - 이 클래스는 @Async 컨텍스트에서 호출되므로 내부 병렬화 불필요
 * - 스레드 낭비 방지를 위해 순차 실행으로 변경
 *
 * 주의: @Primary 제거됨 - 명시적으로 선택해야 사용됩니다.
 * 기본적으로는 KafkaSecurityEventPublisher를 사용하여 이중 발행을 방지합니다.
 *
 * 사용 사례:
 * - CRITICAL 긴급 알림: Redis로 즉시 전파 필요 시
 * - 실시간 대시보드: 모니터링 UI용 실시간 데이터 필요 시
 * - 이중화 요구사항: Kafka 장애 대비 Redis 백업 필요 시
 */
@Slf4j
@RequiredArgsConstructor
public class CompositeSecurityEventPublisher implements SecurityEventPublisher {

    private final KafkaSecurityEventPublisher kafkaPublisher;
    private final RedisSecurityEventPublisher redisPublisher;

    /**
     * 인가 결정 이벤트를 Kafka와 Redis에 순차 발행
     * AI Native v6.0: CompletableFuture 제거 - @Async 컨텍스트에서 이미 비동기 실행
     */
    @Override
    public void publishAuthorizationEvent(AuthorizationDecisionEvent event) {
        log.debug("Publishing authorization event to multiple channels: eventId={}, principal={}",
            event.getEventId(), event.getPrincipal());

        // Kafka 발행
        try {
            kafkaPublisher.publishAuthorizationEvent(event);
        } catch (Exception e) {
            log.error("Failed to publish to Kafka - eventId={}", event.getEventId(), e);
        }

        // Redis 발행
        try {
            redisPublisher.publishAuthorizationEvent(event);
        } catch (Exception e) {
            log.error("Failed to publish to Redis - eventId={}", event.getEventId(), e);
        }

        log.trace("Authorization event published to all channels: eventId={}", event.getEventId());
    }

    /**
     * 보안 사고 이벤트를 Kafka와 Redis에 순차 발행
     * 중요 사고는 즉시 전파가 필요하므로 Redis가 우선
     */
    @Override
    public void publishSecurityIncident(SecurityIncidentEvent event) {
        log.info("Publishing security incident to multiple channels: incidentId={}, severity={}",
            event.getIncidentId(), event.getSeverity());

        // 중요 사고는 Redis 먼저 (빠른 전파)
        try {
            redisPublisher.publishSecurityIncident(event);
        } catch (Exception e) {
            log.error("Failed to publish incident to Redis", e);
        }

        // Kafka로 영구 저장
        try {
            kafkaPublisher.publishSecurityIncident(event);
        } catch (Exception e) {
            log.error("Failed to publish incident to Kafka", e);
        }
    }

    /**
     * 위협 탐지 이벤트를 Kafka와 Redis에 순차 발행
     * 고위험 위협은 즉시 대응이 필요하므로 Redis 우선
     */
    @Override
    public void publishThreatDetection(ThreatDetectionEvent event) {
        log.info("Publishing threat detection to multiple channels: threatId={}, level={}",
            event.getThreatId(), event.getThreatLevel());

        // 고위험 위협은 Redis 먼저 (빠른 대응)
        if (event.getThreatLevel() == ThreatDetectionEvent.ThreatLevel.CRITICAL ||
            event.getThreatLevel() == ThreatDetectionEvent.ThreatLevel.HIGH) {
            try {
                redisPublisher.publishThreatDetection(event);
            } catch (Exception e) {
                log.error("Failed to publish critical threat to Redis", e);
            }
        }

        // Kafka로 영구 저장
        try {
            kafkaPublisher.publishThreatDetection(event);
        } catch (Exception e) {
            log.error("Failed to publish threat to Kafka", e);
        }

        // 일반 위협도 Redis로 전파
        if (event.getThreatLevel() != ThreatDetectionEvent.ThreatLevel.CRITICAL &&
            event.getThreatLevel() != ThreatDetectionEvent.ThreatLevel.HIGH) {
            try {
                redisPublisher.publishThreatDetection(event);
            } catch (Exception e) {
                log.error("Failed to publish threat to Redis", e);
            }
        }
    }

    /**
     * 감사 이벤트를 Kafka와 Redis에 순차 발행
     * 감사 로그는 주로 Kafka에 저장, Redis는 최근 이벤트만
     */
    @Override
    public void publishAuditEvent(AuditEvent event) {
        log.trace("Publishing audit event to multiple channels: eventId={}", event.getEventId());

        // Kafka 발행
        try {
            kafkaPublisher.publishAuditEvent(event);
        } catch (Exception e) {
            log.error("Failed to publish audit to Kafka - eventId={}", event.getEventId(), e);
        }

        // Redis 발행
        try {
            redisPublisher.publishAuditEvent(event);
        } catch (Exception e) {
            log.error("Failed to publish audit to Redis - eventId={}", event.getEventId(), e);
        }
    }

    /**
     * 인증 성공 이벤트를 Kafka와 Redis에 순차 발행
     * Zero Trust: 모든 성공 인증을 실시간 분석
     */
    @Override
    public void publishAuthenticationSuccess(AuthenticationSuccessEvent event) {
        log.debug("Publishing authentication success to multiple channels: eventId={}, user={}",
            event.getEventId(), event.getUsername());

        // 이상 징후 감지된 경우 Redis 먼저 (빠른 대응)
        boolean isCritical = event.isAnomalyDetected() ||
            event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.CRITICAL;

        if (isCritical) {
            try {
                redisPublisher.publishAuthenticationSuccess(event);
            } catch (Exception e) {
                log.error("Failed to publish critical auth success to Redis", e);
            }
        }

        // Kafka 발행
        try {
            kafkaPublisher.publishAuthenticationSuccess(event);
        } catch (Exception e) {
            log.error("Failed to publish auth success to Kafka - eventId={}", event.getEventId(), e);
        }

        // 일반 케이스 Redis 발행 (이미 발행된 경우 스킵)
        if (!isCritical) {
            try {
                redisPublisher.publishAuthenticationSuccess(event);
            } catch (Exception e) {
                log.error("Failed to publish auth success to Redis - eventId={}", event.getEventId(), e);
            }
        }
    }

    /**
     * 인증 실패 이벤트를 Kafka와 Redis에 순차 발행
     * 공격 패턴 감지 시 즉시 대응
     */
    @Override
    public void publishAuthenticationFailure(AuthenticationFailureEvent event) {
        log.debug("Publishing authentication failure to multiple channels: eventId={}, user={}",
            event.getEventId(), event.getUsername());

        // 공격 패턴 감지 시 Redis 먼저 (빠른 차단)
        boolean isAttack = event.isBruteForceDetected() || event.isCredentialStuffingDetected() ||
            event.determineAttackType() != AuthenticationFailureEvent.AttackType.NORMAL;

        if (isAttack) {
            try {
                redisPublisher.publishAuthenticationFailure(event);
            } catch (Exception e) {
                log.error("Failed to publish attack pattern to Redis", e);
            }
        }

        // Kafka 발행
        try {
            kafkaPublisher.publishAuthenticationFailure(event);
        } catch (Exception e) {
            log.error("Failed to publish auth failure to Kafka - eventId={}", event.getEventId(), e);
        }

        // 일반 케이스 Redis 발행 (이미 발행된 경우 스킵)
        if (!isAttack) {
            try {
                redisPublisher.publishAuthenticationFailure(event);
            } catch (Exception e) {
                log.error("Failed to publish auth failure to Redis - eventId={}", event.getEventId(), e);
            }
        }
    }

    /**
     * 일반 보안 이벤트를 Kafka와 Redis에 순차 발행
     * AI Native v6.0: CompletableFuture 제거 - 순차 실행으로 변경
     */
    @Override
    public void publishSecurityEvent(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        log.debug("[CompositePublisher] START publishing security event - eventId={}, severity={}, thread={}",
            event.getEventId(), event.getSeverity(), Thread.currentThread().getName());

        // Kafka 발행
        try {
            log.debug("[CompositePublisher] Calling Kafka publisher for eventId={}", event.getEventId());
            kafkaPublisher.publishSecurityEvent(event);
            log.debug("[CompositePublisher] Kafka publisher completed for eventId={}", event.getEventId());
        } catch (Exception e) {
            log.error("[CompositePublisher] Failed to publish event to Kafka - eventId={}",
                event.getEventId(), e);
        }

        // Redis 발행
        try {
            log.debug("[CompositePublisher] Calling Redis publisher for eventId={}", event.getEventId());
            redisPublisher.publishSecurityEvent(event);
            log.debug("[CompositePublisher] Redis publisher completed for eventId={}", event.getEventId());
        } catch (Exception e) {
            log.error("[CompositePublisher] Failed to publish event to Redis - eventId={}",
                event.getEventId(), e);
        }

        long duration = System.currentTimeMillis() - startTime;
        log.debug("[CompositePublisher] COMPLETED publishing to all channels - eventId={}, duration={}ms",
            event.getEventId(), duration);
    }
}
