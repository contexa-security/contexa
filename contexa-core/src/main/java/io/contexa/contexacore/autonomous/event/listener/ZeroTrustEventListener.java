package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class ZeroTrustEventListener {

    private final KafkaSecurityEventPublisher kafkaSecurityEventPublisher;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityDecisionPostProcessor postProcessor;

    @Value("${security.zerotrust.enabled:true}")
    private boolean zeroTrustEnabled;

    @Value("${security.zerotrust.sampling.rate:1.0}")
    private double samplingRate;

    public ZeroTrustEventListener(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            RedisTemplate<String, Object> redisTemplate,
            SecurityDecisionPostProcessor postProcessor) {
        this.kafkaSecurityEventPublisher = kafkaSecurityEventPublisher;
        this.redisTemplate = redisTemplate;
        this.postProcessor = postProcessor;
    }

    @EventListener
    public void handleZeroTrustEvent(ZeroTrustSpringEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            if (!zeroTrustEnabled) {
                return;
            }

            switch (event.getCategory()) {
                case AUTHENTICATION:
                    processAuthenticationEvent(event);
                    break;
                case AUTHORIZATION:
                    processAuthorizationEvent(event);
                    break;
                case SESSION:
                    processSessionEvent(event);
                    break;
                case THREAT:
                    processThreatEvent(event);
                    break;
                case CUSTOM:
                    processCustomEvent(event);
                    break;
                default:
                    log.warn("[ZeroTrustEventListener] Unhandled event category: {}", event.getCategory());
            }

            long duration = System.currentTimeMillis() - startTime;

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process event - category: {}, type: {}, duration: {}ms",
                    event.getCategory(), event.getEventType(), duration, e);
        }
    }

    private void processAuthenticationEvent(ZeroTrustSpringEvent event) {
        String userId = event.getUserId();

        if (ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS.equals(event.getEventType())) {
            if (isLlmChallengeMfa(userId)) {
                processMfaCompletion(event);
                return;
            }
        }

        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processAuthorizationEvent(ZeroTrustSpringEvent event) {
        String userId = event.getUserId();

        if (shouldSkipPublishing(userId)) {
            return;
        }

        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processSessionEvent(ZeroTrustSpringEvent event) {

        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processThreatEvent(ZeroTrustSpringEvent event) {
        log.warn("[ZeroTrustEventListener] Processing threat event - type: {}, user: {}, resource: {}",
                event.getEventType(), event.getUserId(), event.getResource());

        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processCustomEvent(ZeroTrustSpringEvent event) {

        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private boolean isLlmChallengeMfa(String userId) {
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
            }

            return isLlmAction;

        } catch (Exception e) {
            return false;
        }
    }

    private void processMfaCompletion(ZeroTrustSpringEvent event) {

        if (postProcessor != null) {
            SecurityEvent securityEvent = convertToSecurityEvent(event);
            SecurityDecision decision = createMfaSuccessDecision(event);

            postProcessor.updateSessionContext(securityEvent, decision);
            postProcessor.storeInVectorDatabase(securityEvent, decision);

        }
    }

    private SecurityEvent convertToSecurityEvent(ZeroTrustSpringEvent event) {
        SecurityEvent securityEvent = new SecurityEvent();

        securityEvent.setEventId(event.getPayloadValue("eventId", java.util.UUID.randomUUID().toString()));
        securityEvent.setSource(SecurityEvent.EventSource.IAM);
        securityEvent.setTimestamp(LocalDateTime.ofInstant(event.getEventTimestamp(), ZoneId.systemDefault()));
        securityEvent.setUserId(event.getUserId());
        securityEvent.setUserName(event.getPayloadValue("userName"));
        securityEvent.setSessionId(event.getSessionId());
        securityEvent.setSourceIp(event.getClientIp());
        securityEvent.setUserAgent(event.getUserAgent());
        securityEvent.setSeverity(SecurityEvent.Severity.MEDIUM);

        Map<String, Object> metadata = new HashMap<>(event.getPayload());
        securityEvent.setMetadata(metadata);

        return securityEvent;
    }

    private SecurityDecision createMfaSuccessDecision(ZeroTrustSpringEvent event) {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ALLOW)
                .riskScore(0.0)
                .confidence(1.0)
                .reasoning("MFA verification completed successfully")
                .eventId(event.getPayloadValue("eventId", java.util.UUID.randomUUID().toString()))
                .analysisTime(System.currentTimeMillis())
                .build();
    }

    private boolean shouldSkipPublishing(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Boolean isAnalyzing = redisTemplate.hasKey(analysisKey);

            if (Boolean.TRUE.equals(isAnalyzing)) {
                Long ttl = redisTemplate.getExpire(analysisKey);
                if (ttl != null && ttl > 0) {
                    return true;
                }
            }

            return false;

        } catch (Exception e) {
            return false;
        }
    }
}
