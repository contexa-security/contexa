package io.contexa.contexacore.autonomous.orchestrator.strategy;

import io.contexa.contexacore.autonomous.domain.NotificationResult;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.ISoarNotifier;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Realtime Block 처리 전략
 *
 * 극도로 높은 위험 이벤트를 즉시 차단
 * Critical 위협에 대한 즉각적인 대응
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RealtimeBlockStrategy implements ProcessingStrategy {

    private final RedisTemplate<String, Object> redisTemplate;

    @Autowired(required = false)
    private ISoarNotifier soarNotifier;

    @Value("${redis.session.hijack.channel:security:session:hijack:channel}")
    private String sessionHijackChannel;

    @Override
    public ProcessingResult process(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        log.error("[RealtimeBlockStrategy] CRITICAL THREAT DETECTED - Blocking immediately - eventId: {}",
                event.getEventId());

        List<String> executedActions = new ArrayList<>();
        Map<String, Object> metadata = new HashMap<>();

        try {
            // 1. 사용자 계정 차단
            if (event.getUserId() != null) {
                blockUserAccount(event.getUserId());
                executedActions.add("USER_BLOCKED");
                context.addResponseAction("USER_BLOCKED", "User account blocked: " + event.getUserId());
            }

            // 2. IP 차단
            if (event.getSourceIp() != null) {
                blockIpAddress(event.getSourceIp());
                executedActions.add("IP_BLOCKED");
                context.addResponseAction("IP_BLOCKED", "IP address blocked: " + event.getSourceIp());
            }

            // 3. 세션 무효화
            if (event.getSessionId() != null) {
                invalidateSession(event.getSessionId(), event.getUserId());
                executedActions.add("SESSION_INVALIDATED");
                context.addResponseAction("SESSION_INVALIDATED", "Session invalidated: " + event.getSessionId());
            }

            // 4. 긴급 알림 발송
            if (soarNotifier != null) {
                NotificationResult notifyResult = sendCriticalAlert(event, context);
                if (notifyResult.isSuccess()) {
                    executedActions.add("CRITICAL_ALERT_SENT");
                    context.addResponseAction("CRITICAL_ALERT", "Critical alert sent to security team");
                }
            }

            // 5. 격리 조치
            isolateThreat(event, context);
            executedActions.add("THREAT_ISOLATED");
            context.addResponseAction("THREAT_ISOLATED", "Threat isolated and contained");

            metadata.put("blockedAt", System.currentTimeMillis());
            metadata.put("threatLevel", "CRITICAL");
            metadata.put("immediateAction", true);

            log.info("[RealtimeBlockStrategy] Critical threat blocked - eventId: {}, actions: {}",
                    event.getEventId(), executedActions);

            return ProcessingResult.builder()
                    .success(true)
                    .processingPath(ProcessingResult.ProcessingPath.HOT_PATH)
                    .executedActions(executedActions)
                    .metadata(metadata)
                    .message("Critical threat blocked successfully")
                    .build();

        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Error blocking critical threat: {}", event.getEventId(), e);
            return ProcessingResult.builder()
                    .success(false)
                    .processingPath(ProcessingResult.ProcessingPath.HOT_PATH)
                    .executedActions(executedActions)
                    .message("Blocking error: " + e.getMessage())
                    .build();
        }
    }

    /**
     * 사용자 계정 차단
     */
    private void blockUserAccount(String userId) {
        try {
            String blockKey = "security:blocked:users:" + userId;
            redisTemplate.opsForValue().set(blockKey, true);

            // Trust Score를 0으로 설정
            String trustKey = "security:user:trust:" + userId;
            redisTemplate.opsForValue().set(trustKey, 0.0);

            log.error("[RealtimeBlockStrategy] User account blocked: {}", userId);
        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Failed to block user account: {}", userId, e);
        }
    }

    /**
     * IP 주소 차단
     */
    private void blockIpAddress(String ip) {
        try {
            String blockKey = "security:blocked:ips:" + ip;
            redisTemplate.opsForValue().set(blockKey, true, Duration.ofDays(30));

            log.error("[RealtimeBlockStrategy] IP address blocked: {}", ip);
        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Failed to block IP address: {}", ip, e);
        }
    }

    /**
     * 세션 무효화
     */
    private void invalidateSession(String sessionId, String userId) {
        try {
            // 1. 세션 삭제
            String sessionKey = "security:sessions:" + sessionId;
            redisTemplate.delete(sessionKey);

            // 2. 세션 하이재킹 채널로 이벤트 발행 (SecurityPlaneAgentOld 로직 복구)
            Map<String, Object> invalidationEvent = new HashMap<>();
            invalidationEvent.put("sessionId", sessionId);
            invalidationEvent.put("userId", userId);
            invalidationEvent.put("reason", "CRITICAL_THREAT");
            invalidationEvent.put("detectedAt", System.currentTimeMillis());
            invalidationEvent.put("invalidatedBy", "RealtimeBlockStrategy");

            redisTemplate.convertAndSend(sessionHijackChannel, invalidationEvent);

            log.error("[RealtimeBlockStrategy] Session invalidated and hijack event published: {} for user: {}", sessionId, userId);
        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Failed to invalidate session: {}", sessionId, e);
        }
    }

    /**
     * 긴급 알림 발송
     */
    private NotificationResult sendCriticalAlert(SecurityEvent event, SecurityEventContext context) {
        try {
            Map<String, Object> notificationData = new HashMap<>();
            notificationData.put("severity", "CRITICAL");
            notificationData.put("eventId", event.getEventId());
            notificationData.put("eventType", event.getEventType());
            notificationData.put("userId", event.getUserId());
            notificationData.put("sourceIp", event.getSourceIp());
            notificationData.put("message", "CRITICAL SECURITY THREAT DETECTED - IMMEDIATE ACTION REQUIRED");

            return soarNotifier.notifyCriticalEvent(event, notificationData);
        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Failed to send critical alert", e);
            return NotificationResult.failure("alert-failed", "Alert failed: " + e.getMessage());
        }
    }

    /**
     * 위협 격리
     */
    private void isolateThreat(SecurityEvent event, SecurityEventContext context) {
        try {
            // 격리 네임스페이스에 이벤트 정보 저장
            String isolationKey = "security:isolation:" + event.getEventId();
            Map<String, Object> isolationData = new HashMap<>();
            isolationData.put("event", event);
            isolationData.put("isolatedAt", System.currentTimeMillis());
            isolationData.put("reason", "Critical threat auto-isolation");

            redisTemplate.opsForHash().putAll(isolationKey, isolationData);
            redisTemplate.expire(isolationKey, Duration.ofDays(90));

            log.error("[RealtimeBlockStrategy] Threat isolated: {}", event.getEventId());
        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Failed to isolate threat: {}", event.getEventId(), e);
        }
    }

    @Override
    public ProcessingMode getSupportedMode() {
        return ProcessingMode.REALTIME_BLOCK;
    }
}