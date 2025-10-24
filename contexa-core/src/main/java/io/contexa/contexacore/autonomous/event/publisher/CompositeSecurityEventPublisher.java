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
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

/**
 * 복합 보안 이벤트 발행자
 *
 * Kafka와 Redis를 동시에 사용하여 이벤트를 발행합니다.
 * - Kafka: 영구 저장 및 순차 처리를 위한 이벤트 스트림
 * - Redis: 실시간 전파 및 빠른 접근을 위한 캐시
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
@Component
@RequiredArgsConstructor
public class CompositeSecurityEventPublisher implements SecurityEventPublisher {
    
    private final KafkaSecurityEventPublisher kafkaPublisher;
    private final RedisSecurityEventPublisher redisPublisher;
    
    /**
     * 인가 결정 이벤트를 Kafka와 Redis에 동시 발행
     * 비동기 처리로 성능 영향 최소화
     */
    @Override
    public void publishAuthorizationEvent(AuthorizationDecisionEvent event) {
        log.debug("Publishing authorization event to multiple channels: eventId={}, principal={}",
            event.getEventId(), event.getPrincipal());

        // Kafka와 Redis에 병렬로 발행
        CompletableFuture<Void> kafkaFuture = CompletableFuture.runAsync(() -> {
            try {
                kafkaPublisher.publishAuthorizationEvent(event);
            } catch (Exception e) {
                log.error("Failed to publish to Kafka - eventId={}", event.getEventId(), e);
                throw new RuntimeException("Kafka publishing failed", e);
            }
        });

        CompletableFuture<Void> redisFuture = CompletableFuture.runAsync(() -> {
            try {
                redisPublisher.publishAuthorizationEvent(event);
            } catch (Exception e) {
                log.error("Failed to publish to Redis - eventId={}", event.getEventId(), e);
                throw new RuntimeException("Redis publishing failed", e);
            }
        });

        // 두 작업 완료 대기 및 에러 처리
        CompletableFuture.allOf(kafkaFuture, redisFuture).whenComplete((result, ex) -> {
            if (ex == null) {
                log.trace("Authorization event published to all channels: eventId={}", event.getEventId());
            } else {
                log.error("Partial failure in composite publish - eventId={}: {}",
                    event.getEventId(), ex.getMessage());
            }
        });
    }
    
    /**
     * 보안 사고 이벤트를 Kafka와 Redis에 동시 발행
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
     * 위협 탐지 이벤트를 Kafka와 Redis에 동시 발행
     * 고위험 위협은 즉시 대응이 필요하므로 Redis 우선
     */
    @Override
    public void publishThreatDetection(ThreatDetectionEvent event) {
        log.info("Publishing threat detection to multiple channels: threatId={}, level={}", 
            event.getThreatId(), event.getThreatLevel());
        
        // 고위험 위협은 Redis 먼저
        if (event.getThreatLevel() == ThreatDetectionEvent.ThreatLevel.CRITICAL ||
            event.getThreatLevel() == ThreatDetectionEvent.ThreatLevel.HIGH) {
            try {
                redisPublisher.publishThreatDetection(event);
            } catch (Exception e) {
                log.error("Failed to publish critical threat to Redis", e);
            }
        }
        
        // 모든 위협은 Kafka로 저장
        CompletableFuture.runAsync(() -> {
            try {
                kafkaPublisher.publishThreatDetection(event);
            } catch (Exception e) {
                log.error("Failed to publish threat to Kafka", e);
            }
        });
        
        // 일반 위협도 Redis로 전파
        if (event.getThreatLevel() != ThreatDetectionEvent.ThreatLevel.CRITICAL &&
            event.getThreatLevel() != ThreatDetectionEvent.ThreatLevel.HIGH) {
            CompletableFuture.runAsync(() -> {
                try {
                    redisPublisher.publishThreatDetection(event);
                } catch (Exception e) {
                    log.error("Failed to publish threat to Redis", e);
                }
            });
        }
    }
    
    /**
     * 감사 이벤트를 Kafka와 Redis에 동시 발행
     * 감사 로그는 주로 Kafka에 저장, Redis는 최근 이벤트만
     */
    @Override
    public void publishAuditEvent(AuditEvent event) {
        log.trace("Publishing audit event to multiple channels: eventId={}", event.getEventId());

        // Kafka와 Redis에 병렬로 발행
        CompletableFuture.allOf(
            CompletableFuture.runAsync(() -> {
                try {
                    kafkaPublisher.publishAuditEvent(event);
                } catch (Exception e) {
                    log.error("Failed to publish audit to Kafka - eventId={}", event.getEventId(), e);
                    throw new RuntimeException("Kafka publishing failed", e);
                }
            }),
            CompletableFuture.runAsync(() -> {
                try {
                    redisPublisher.publishAuditEvent(event);
                } catch (Exception e) {
                    log.error("Failed to publish audit to Redis - eventId={}", event.getEventId(), e);
                    throw new RuntimeException("Redis publishing failed", e);
                }
            })
        ).whenComplete((result, ex) -> {
            if (ex != null) {
                log.warn("Partial failure in audit publish - eventId={}: {}",
                    event.getEventId(), ex.getMessage());
            }
        });
    }
    
    /**
     * 인증 성공 이벤트를 Kafka와 Redis에 동시 발행
     * Zero Trust: 모든 성공 인증을 실시간 분석
     */
    @Override
    public void publishAuthenticationSuccess(AuthenticationSuccessEvent event) {
        log.debug("Publishing authentication success to multiple channels: eventId={}, user={}", 
            event.getEventId(), event.getUsername());
        
        // 이상 징후 감지된 경우 Redis 먼저 (빠른 대응)
        if (event.isAnomalyDetected() || 
            event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.CRITICAL) {
            try {
                redisPublisher.publishAuthenticationSuccess(event);
            } catch (Exception e) {
                log.error("Failed to publish critical auth success to Redis", e);
            }
        }
        
        // Kafka와 Redis에 병렬로 발행
        CompletableFuture.allOf(
            CompletableFuture.runAsync(() -> {
                try {
                    kafkaPublisher.publishAuthenticationSuccess(event);
                } catch (Exception e) {
                    log.error("Failed to publish auth success to Kafka - eventId={}", event.getEventId(), e);
                    throw new RuntimeException("Kafka publishing failed", e);
                }
            }),
            CompletableFuture.runAsync(() -> {
                if (!event.isAnomalyDetected() &&
                    event.calculateRiskLevel() != AuthenticationSuccessEvent.RiskLevel.CRITICAL) {
                    try {
                        redisPublisher.publishAuthenticationSuccess(event);
                    } catch (Exception e) {
                        log.error("Failed to publish auth success to Redis - eventId={}", event.getEventId(), e);
                        throw new RuntimeException("Redis publishing failed", e);
                    }
                }
            })
        ).whenComplete((result, ex) -> {
            if (ex != null) {
                log.warn("Partial failure in auth success publish - eventId={}: {}",
                    event.getEventId(), ex.getMessage());
            }
        });
    }
    
    /**
     * 인증 실패 이벤트를 Kafka와 Redis에 동시 발행
     * 공격 패턴 감지 시 즉시 대응
     */
    @Override
    public void publishAuthenticationFailure(AuthenticationFailureEvent event) {
        log.debug("Publishing authentication failure to multiple channels: eventId={}, user={}", 
            event.getEventId(), event.getUsername());
        
        // 공격 패턴 감지 시 Redis 먼저 (빠른 차단)
        if (event.isBruteForceDetected() || event.isCredentialStuffingDetected() ||
            event.determineAttackType() != AuthenticationFailureEvent.AttackType.NORMAL) {
            try {
                redisPublisher.publishAuthenticationFailure(event);
            } catch (Exception e) {
                log.error("Failed to publish attack pattern to Redis", e);
            }
        }
        
        // Kafka와 Redis에 병렬로 발행
        CompletableFuture.allOf(
            CompletableFuture.runAsync(() -> {
                try {
                    kafkaPublisher.publishAuthenticationFailure(event);
                } catch (Exception e) {
                    log.error("Failed to publish auth failure to Kafka - eventId={}", event.getEventId(), e);
                    throw new RuntimeException("Kafka publishing failed", e);
                }
            }),
            CompletableFuture.runAsync(() -> {
                if (!event.isBruteForceDetected() && !event.isCredentialStuffingDetected() &&
                    event.determineAttackType() == AuthenticationFailureEvent.AttackType.NORMAL) {
                    try {
                        redisPublisher.publishAuthenticationFailure(event);
                    } catch (Exception e) {
                        log.error("Failed to publish auth failure to Redis - eventId={}", event.getEventId(), e);
                        throw new RuntimeException("Redis publishing failed", e);
                    }
                }
            })
        ).whenComplete((result, ex) -> {
            if (ex != null) {
                log.warn("Partial failure in auth failure publish - eventId={}: {}",
                    event.getEventId(), ex.getMessage());
            }
        });
    }
    
    /**
     * 일반 보안 이벤트를 Kafka와 Redis에 동시 발행
     */
    @Override
    public void publishSecurityEvent(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        log.debug("[CompositePublisher] START publishing security event - eventId={}, type={}, thread={}",
            event.getEventId(), event.getEventType(), Thread.currentThread().getName());

        try {
            // Kafka와 Redis에 병렬로 발행
            CompletableFuture<Void> kafkaFuture = CompletableFuture.runAsync(() -> {
                try {
                    log.debug("[CompositePublisher] Calling Kafka publisher for eventId={}", event.getEventId());
                    kafkaPublisher.publishSecurityEvent(event);
                    log.debug("[CompositePublisher] Kafka publisher completed for eventId={}", event.getEventId());
                } catch (Exception e) {
                    log.error("[CompositePublisher] Failed to publish event to Kafka - eventId={}",
                        event.getEventId(), e);
                }
            });

            CompletableFuture<Void> redisFuture = CompletableFuture.runAsync(() -> {
                try {
                    log.debug("[CompositePublisher] Calling Redis publisher for eventId={}", event.getEventId());
                    redisPublisher.publishSecurityEvent(event);
                    log.debug("[CompositePublisher] Redis publisher completed for eventId={}", event.getEventId());
                } catch (Exception e) {
                    log.error("[CompositePublisher] Failed to publish event to Redis - eventId={}",
                        event.getEventId(), e);
                }
            });

            // 중요: 완료를 기다림 (이전에는 기다리지 않았음!)
            CompletableFuture.allOf(kafkaFuture, redisFuture).join();

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[CompositePublisher] COMPLETED publishing to all channels - eventId={}, duration={}ms",
                event.getEventId(), duration);

        } catch (Exception e) {
            log.error("[CompositePublisher] ERROR during event publishing - eventId={}",
                event.getEventId(), e);
            throw new RuntimeException("Failed to publish security event", e);
        }
    }
}