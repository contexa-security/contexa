package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import io.contexa.contexacore.autonomous.event.domain.HttpRequestEvent;
import io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.decision.EventTier;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static io.contexa.contexacore.autonomous.event.decision.EventTier.BENIGN;
import static io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent.ThreatLevel.*;

@Slf4j
public class ZeroTrustEventListener {

    private final KafkaSecurityEventPublisher kafkaSecurityEventPublisher;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityDecisionPostProcessor postProcessor;

    public ZeroTrustEventListener(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            RedisTemplate<String, Object> redisTemplate,
            SecurityDecisionPostProcessor postProcessor) {
        this.kafkaSecurityEventPublisher = kafkaSecurityEventPublisher;
        this.redisTemplate = redisTemplate;
        this.postProcessor = postProcessor;
    }
    
    @Value("${security.zerotrust.enabled:true}")
    private boolean zeroTrustEnabled;
    
    @Value("${security.zerotrust.sampling.rate:1.0}")
    private double samplingRate;
    
    
    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        long startTime = System.currentTimeMillis();
        try {
            if (!zeroTrustEnabled) {
                log.debug("Zero Trust is disabled, skipping event processing");
                return;
            }

            if (isLlmChallengeMfa(event)) {
                SecurityEvent securityEvent = convertToSecurityEvent(event);
                SecurityDecision decision = createMfaSuccessDecision(event);

                if (postProcessor != null) {
                    postProcessor.updateSessionContext(securityEvent, decision);
                    postProcessor.storeInVectorDatabase(securityEvent, decision);
                }
                return;
            }

            log.info("[ZeroTrustEventListener] Publishing authentication success event - EventID: {}, User: {}, SessionId: {}, Risk: {}",
                    event.getEventId(), event.getUsername(), event.getSessionId(), event.calculateRiskLevel());
            kafkaSecurityEventPublisher.publishAuthenticationSuccess(event);

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[ZeroTrustEventListener] Event queued for Kafka successfully - EventID: {}, duration: {}ms",
                event.getEventId(), duration);



        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process authentication success event - duration: {}ms", duration, e);
        }
    }
    
    /**
     * 인증 실패 이벤트 처리
     */
    @EventListener
    public void handleAuthenticationFailure(AuthenticationFailureEvent event) {
        long startTime = System.currentTimeMillis();
        try {
            if (!zeroTrustEnabled) {
                return;
            }

            log.info("[ZeroTrustEventListener] Authentication failure event received - user: {}, attempts: {}",
                    event.getUsername(), event.getFailureCount());

            kafkaSecurityEventPublisher.publishAuthenticationFailure(event);

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[ZeroTrustEventListener] Auth failure event queued - EventID: {}, duration: {}ms",
                event.getEventId(), duration);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process authentication failure event - duration: {}ms", duration, e);
        }
    }
    
    /**
     * AuthenticationSuccessEvent를 SecurityEvent로 변환
     */
    private SecurityEvent convertToSecurityEvent(AuthenticationSuccessEvent authEvent) {
        SecurityEvent event = new SecurityEvent();
        
        event.setEventId(authEvent.getEventId());
        // AI Native v4.0.0: eventType 제거 - severity, source로 분류
        event.setSource(SecurityEvent.EventSource.IAM);
        event.setTimestamp(authEvent.getEventTimestamp());
        
        // 사용자 정보 (필수)
        event.setUserId(authEvent.getUserId());
        event.setUserName(authEvent.getUsername());
        event.setSessionId(authEvent.getSessionId());
        
        // 네트워크 정보
        event.setSourceIp(authEvent.getSourceIp());
        event.setUserAgent(authEvent.getUserAgent());

        // AI Native v4.1.0: Severity 매핑 제거 - LLM이 원시 데이터로 직접 판단
        event.setSeverity(SecurityEvent.Severity.MEDIUM);

        // 메타데이터
        Map<String, Object> metadata = new HashMap<>();

        // AI Native: 원시 데이터 제공 (LLM이 직접 위험도 평가)
        metadata.put("authz.trustScore", authEvent.getTrustScore());
        metadata.put("auth.riskLevel", authEvent.calculateRiskLevel().name());

        // 이상 징후 - metadata로 이동
        if (authEvent.isAnomalyDetected()) {
            metadata.put("auth.threatType", "ANOMALY_DETECTED");
            event.setBlocked(false); // 성공했지만 의심스러운 경우
        }
        metadata.put("authenticationType", authEvent.getAuthenticationType());
        metadata.put("mfaCompleted", authEvent.isMfaCompleted());
        metadata.put("mfaMethod", authEvent.getMfaMethod());
        metadata.put("deviceId", authEvent.getDeviceId());

        if (authEvent.getRiskIndicators() != null) {
            metadata.putAll(authEvent.getRiskIndicators());
        }
        if (authEvent.getMetadata() != null) {
            metadata.putAll(authEvent.getMetadata());
        }
        event.setMetadata(metadata);
        
        return event;
    }
    
    private boolean isLlmChallengeMfa(AuthenticationSuccessEvent event) {
        String userId = event.getUserId();
        if (userId == null || userId.isBlank()) {
            return false;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object previousAction = redisTemplate.opsForHash().get(analysisKey, "previousAction");

            String actionStr = String.valueOf(previousAction);
            boolean isLlmAction = "CHALLENGE".equals(actionStr) || "ESCALATE".equals(actionStr);

            if (isLlmAction) {
                redisTemplate.opsForHash().delete(analysisKey, "previousAction");
                log.debug("[ZeroTrustEventListener] LLM {} MFA 확인 - previousAction 정리 완료: userId={}",
                    actionStr, userId);
            }

            return isLlmAction;

        } catch (Exception e) {
            log.debug("[ZeroTrustEventListener] previousAction 확인 실패 - 안전하게 업데이트 생략: userId={}", userId, e);
            return false;  // 확인 실패 시 안전하게 업데이트 생략
        }
    }

    private SecurityDecision createMfaSuccessDecision(AuthenticationSuccessEvent event) {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ALLOW)
                .riskScore(0.0)
                .confidence(1.0)
                .reasoning("MFA verification completed successfully")
                .eventId(event.getEventId())
                .analysisTime(System.currentTimeMillis())
                .build();
    }
}