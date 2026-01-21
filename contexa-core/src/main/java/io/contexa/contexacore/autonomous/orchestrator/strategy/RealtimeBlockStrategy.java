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

@Slf4j
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
            
            if (event.getUserId() != null) {
                blockUserAccount(event.getUserId());
                executedActions.add("USER_BLOCKED");
                context.addResponseAction("USER_BLOCKED", "User account blocked: " + event.getUserId());
            }

            if (event.getSourceIp() != null) {
                blockIpAddress(event.getSourceIp());
                executedActions.add("IP_BLOCKED");
                context.addResponseAction("IP_BLOCKED", "IP address blocked: " + event.getSourceIp());
            }

            if (event.getSessionId() != null) {
                invalidateSession(event.getSessionId(), event.getUserId());
                executedActions.add("SESSION_INVALIDATED");
                context.addResponseAction("SESSION_INVALIDATED", "Session invalidated: " + event.getSessionId());
            }

            if (soarNotifier != null) {
                NotificationResult notifyResult = sendCriticalAlert(event, context);
                if (notifyResult.isSuccess()) {
                    executedActions.add("CRITICAL_ALERT_SENT");
                    context.addResponseAction("CRITICAL_ALERT", "Critical alert sent to security team");
                }
            }

            isolateThreat(event, context);
            executedActions.add("THREAT_ISOLATED");
            context.addResponseAction("THREAT_ISOLATED", "Threat isolated and contained");

            metadata.put("blockedAt", System.currentTimeMillis());
            metadata.put("threatLevel", "CRITICAL");
            metadata.put("immediateAction", true);

            return ProcessingResult.builder()
                    .success(true)
                    .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                    .executedActions(executedActions)
                    .metadata(metadata)
                    .message("Critical threat blocked successfully")
                    .build();

        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Error blocking critical threat: {}", event.getEventId(), e);
            return ProcessingResult.builder()
                    .success(false)
                    .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                    .executedActions(executedActions)
                    .message("Blocking error: " + e.getMessage())
                    .build();
        }
    }

    private void blockUserAccount(String userId) {
        try {
            String blockKey = "security:blocked:users:" + userId;
            redisTemplate.opsForValue().set(blockKey, true);

            String trustKey = "security:user:trust:" + userId;
            redisTemplate.opsForValue().set(trustKey, 0.0);

            log.error("[RealtimeBlockStrategy] User account blocked: {}", userId);
        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Failed to block user account: {}", userId, e);
        }
    }

    private void blockIpAddress(String ip) {
        try {
            String blockKey = "security:blocked:ips:" + ip;
            redisTemplate.opsForValue().set(blockKey, true, Duration.ofDays(30));

            log.error("[RealtimeBlockStrategy] IP address blocked: {}", ip);
        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Failed to block IP address: {}", ip, e);
        }
    }

    private void invalidateSession(String sessionId, String userId) {
        try {
            
            String sessionKey = "security:sessions:" + sessionId;
            redisTemplate.delete(sessionKey);

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

    private NotificationResult sendCriticalAlert(SecurityEvent event, SecurityEventContext context) {
        try {
            Map<String, Object> notificationData = new HashMap<>();
            notificationData.put("severity", "CRITICAL");
            notificationData.put("eventId", event.getEventId());
            
            notificationData.put("eventSeverity", event.getSeverity());
            notificationData.put("userId", event.getUserId());
            notificationData.put("sourceIp", event.getSourceIp());
            notificationData.put("message", "CRITICAL SECURITY THREAT DETECTED - IMMEDIATE ACTION REQUIRED");

            return soarNotifier.notifyCriticalEvent(event, notificationData);
        } catch (Exception e) {
            log.error("[RealtimeBlockStrategy] Failed to send critical alert", e);
            return NotificationResult.failure("alert-failed", "Alert failed: " + e.getMessage());
        }
    }

    private void isolateThreat(SecurityEvent event, SecurityEventContext context) {
        try {
            
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