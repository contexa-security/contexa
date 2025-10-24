package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.notification.UnifiedNotificationService;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * 세션 무효화 핸들러
 *
 * Threat Score 기반 세션 무효화 처리를 담당합니다.
 * 기존 AIReactiveSecurityContextRepository의 onMessage 기능을 이관받아
 * SecurityEventProcessingOrchestrator 핸들러 체인에 통합됩니다.
 *
 * 핵심 기능:
 * - Threat Score 임계값 기반 세션 무효화
 * - 세션 위협 이벤트 Redis pub/sub 처리
 * - 감사 로그 및 알림 발송
 * - SecurityEventProcessingOrchestrator와 통합
 *
 * @author AI3Security
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SessionInvalidationHandler implements SecurityEventHandler {

    private final RedisTemplate<String, Object> redisTemplate;
    private final UnifiedNotificationService notificationService;
    private final AuditLogRepository auditLogRepository;

    // Threat Score 임계값 설정 (외부 설정 사용)
    @Value("${security.session.threat.thresholds.monitoring:0.5}")
    private double monitoringThreshold;

    @Value("${security.session.threat.thresholds.grace-period:0.7}")
    private double gracePeriodThreshold;

    @Value("${security.session.threat.thresholds.invalidation:0.9}")
    private double invalidationThreshold;

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();

        // 세션 관련 위협 이벤트만 처리
        if (!isSessionThreatEvent(event)) {
            return true; // 다음 핸들러로 계속 진행
        }

        log.info("[SessionInvalidationHandler] Processing session threat event - eventId: {}, userId: {}",
                event.getEventId(), event.getUserId());

        try {
            // 1. Threat Score 확인
            double threatScore = getThreatScore(event.getUserId());

            // 2. 임계값 확인 및 세션 무효화 결정
            if (threatScore >= monitoringThreshold) {
//                processSessionInvalidation(event, threatScore);
                context.addMetadata("sessionInvalidated", true);
                context.addMetadata("threatScore", threatScore);
            } else {
                log.debug("[SessionInvalidationHandler] Threat score {} below threshold {} for user: {}",
                        threatScore, monitoringThreshold, event.getUserId());
                context.addMetadata("sessionInvalidated", false);
            }

        } catch (Exception e) {
            log.error("[SessionInvalidationHandler] Failed to process session invalidation for event: {}",
                    event.getEventId(), e);
            context.addMetadata("sessionInvalidationError", e.getMessage());
        }

        return true; // 다음 핸들러로 계속 진행
    }

    /**
     * 세션 위협 이벤트 여부 확인
     */
    private boolean isSessionThreatEvent(SecurityEvent event) {
        if (event.getEventType() == null) {
            return false;
        }

        // 세션 관련 이벤트 타입 확인
        return switch (event.getEventType()) {
            case THREAT_DETECTED, ANOMALY_DETECTED, AUTH_FAILURE, SUSPICIOUS_ACTIVITY -> true;
            default ->
                // 이벤트 메타데이터에서 세션 위협 지표 확인
                    event.getSessionId() != null ||
                            (event.getMetadata() != null &&
                                    event.getMetadata().containsKey("sessionHijackingSuspected"));
        };
    }

    /**
     * Threat Score 조회
     */
    private double getThreatScore(String userId) {
        if (userId == null) {
            return 0.0;
        }

        try {
            String threatScoreKey = ZeroTrustRedisKeys.threatScore(userId);
            Object score = redisTemplate.opsForValue().get(threatScoreKey);

            if (score instanceof Number) {
                return ((Number) score).doubleValue();
            } else if (score instanceof String) {
                return Double.parseDouble((String) score);
            }

        } catch (Exception e) {
            log.error("[SessionInvalidationHandler] Failed to get threat score for user: {}", userId, e);
        }

        return 0.0; // 기본값
    }

    /**
     * 세션 무효화 처리 - 즉시 무효화 패턴
     * 위협 수준에 따라 즉시 세션 삭제 또는 경고
     */
    private void processSessionInvalidation(SecurityEvent event, double threatScore) {
        String userId = event.getUserId();
        String sessionId = event.getSessionId();

        try {
            // 위협 수준에 따른 처리
            if (threatScore >= invalidationThreshold) {
                // 즉시 세션 삭제
                String sessionKey = "spring:session:sessions:" + sessionId;
                redisTemplate.delete(sessionKey);

                // 세션 인덱스도 삭제
                String indexKey = "spring:session:sessions:expirations:" + sessionId;
                redisTemplate.delete(indexKey);

                log.info("[SessionInvalidationHandler] Session invalidated immediately - userId: {}, sessionId: {}, threatScore: {}",
                        userId, sessionId, threatScore);

            } else if (threatScore >= gracePeriodThreshold) {
                // 경고만 (세션 유지)
                log.warn("[SessionInvalidationHandler] High threat detected but below invalidation threshold - userId: {}, threatScore: {}",
                        userId, threatScore);
            } else {
                // 모니터링만
                log.info("[SessionInvalidationHandler] Session marked for monitoring - userId: {}, threatScore: {}",
                        userId, threatScore);
            }

            // 감사 로그 기록 (모든 레벨)
            logSessionInvalidationEvent(event, threatScore);

            // 알림 발송 (모든 레벨)
            sendSessionInvalidationAlert(event, threatScore);

        } catch (Exception e) {
            log.error("[SessionInvalidationHandler] Failed to process session invalidation", e);
        }
    }





    /**
     * 감사 로그 기록
     */
    private void logSessionInvalidationEvent(SecurityEvent event, double threatScore) {
        try {
            AuditLog auditLog = AuditLog.builder()
                .principalName(event.getUserId())
                .resourceIdentifier("SESSION_INVALIDATION")
                .action("SESSION_THREAT_INVALIDATION")
                .decision("INVALIDATE")
                .reason(String.format("High threat score detected: %.3f", threatScore))
                .outcome("SESSION_INVALIDATED")
                .resourceUri("/session/threat") // 요청 경로 정보가 없으므로 고정값 사용
                .clientIp(event.getSourceIp())
                .details(String.format("SessionId: %s, ThreatScore: %.3f",
                        event.getSessionId(), threatScore))
                .build();

            auditLogRepository.save(auditLog);
            log.info("[AUDIT] Session invalidation logged for user: {}", event.getUserId());

        } catch (Exception e) {
            log.error("[SessionInvalidationHandler] Failed to log session invalidation event", e);
        }
    }

    /**
     * 세션 무효화 알림 발송
     */
    private void sendSessionInvalidationAlert(SecurityEvent event, double threatScore) {
        if (notificationService == null) {
            log.warn("[SessionInvalidationHandler] NotificationService not available");
            return;
        }

        try {
            // 보안 이벤트 생성 (invalidationThreshold 사용)
            SecurityEvent alertEvent = SecurityEvent.builder()
                .eventType(SecurityEvent.EventType.ACCESS_DENIED)
                .severity(threatScore >= invalidationThreshold ?
                         SecurityEvent.Severity.CRITICAL : SecurityEvent.Severity.HIGH)
                .userId(event.getUserId())
                .sessionId(event.getSessionId())
                .sourceIp(event.getSourceIp())
                .userAgent(event.getUserAgent())
                .description(String.format("세션이 위협 점수(%.3f)로 인해 처리되었습니다", threatScore))
                .targetResource("SESSION")
                .build();

            // 위협 지표 생성
            io.contexa.contexacore.autonomous.domain.ThreatIndicators indicators =
                io.contexa.contexacore.autonomous.domain.ThreatIndicators.builder()
                .riskScore(threatScore * 100)  // 0-100 범위로 변환
                .riskLevel(threatScore >= invalidationThreshold ? "CRITICAL" : "HIGH")
                .build();

            // 알림 발송
            notificationService.sendSecurityEventNotification(alertEvent, indicators)
                .subscribe(
                    result -> log.info("[SessionInvalidationHandler] Session invalidation alert sent for user: {}",
                            event.getUserId()),
                    error -> log.error("[SessionInvalidationHandler] Failed to send session invalidation alert", error)
                );

        } catch (Exception e) {
            log.error("[SessionInvalidationHandler] Error sending session invalidation alert", e);
        }
    }



    @Override
    public boolean canHandle(SecurityEventContext context) {
        return context != null &&
               context.getSecurityEvent() != null &&
               isSessionThreatEvent(context.getSecurityEvent());
    }

    @Override
    public void handleError(SecurityEventContext context, Exception error) {
        log.error("[SessionInvalidationHandler] Error handling context: {}",
                context.getSecurityEvent().getEventId(), error);
        context.addMetadata("sessionInvalidationHandlerError", error.getMessage());
    }

    @Override
    public String getName() {
        return "SessionInvalidationHandler";
    }

    @Override
    public int getOrder() {
        return 70; // TrustScoreHandler(55) 이후, MetricsHandler(60) 이후
    }

    // Redis Pub/Sub 관련 메서드들 제거됨
    // 핸들러 체인에서 직접 이벤트를 받아 처리하는 것으로 단순화
}