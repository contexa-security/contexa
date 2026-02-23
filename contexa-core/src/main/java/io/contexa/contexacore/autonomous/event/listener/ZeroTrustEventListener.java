package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.RedisTemplate;

@Slf4j
public class ZeroTrustEventListener {

    private final KafkaSecurityEventPublisher kafkaSecurityEventPublisher;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;

    public ZeroTrustEventListener(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            RedisTemplate<String, Object> redisTemplate,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        this.kafkaSecurityEventPublisher = kafkaSecurityEventPublisher;
        this.redisTemplate = redisTemplate;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
    }

    @EventListener
    public void handleZeroTrustEvent(ZeroTrustSpringEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            if (!securityZeroTrustProperties.isEnabled()) {
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
                    log.error("[ZeroTrustEventListener] Unhandled event category: {}", event.getCategory());
            }

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process event - category: {}, type: {}, duration: {}ms",
                    event.getCategory(), event.getEventType(), duration, e);
        }
    }

    private void processAuthenticationEvent(ZeroTrustSpringEvent event) {
        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processAuthorizationEvent(ZeroTrustSpringEvent event) {
        String userId = event.getUserId();

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(
                event.getSessionId(), event.getClientIp(), event.getUserAgent());
        if (shouldSkipPublishing(userId, contextBindingHash)) {
            return;
        }
        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processSessionEvent(ZeroTrustSpringEvent event) {
        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processThreatEvent(ZeroTrustSpringEvent event) {
        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processCustomEvent(ZeroTrustSpringEvent event) {
        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    private boolean shouldSkipPublishing(String userId, String contextBindingHash) {
        if (userId == null || userId.isBlank()) {
            return false;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Boolean hasKey = redisTemplate.hasKey(analysisKey);

            if (hasKey) {
                long ttl = redisTemplate.getExpire(analysisKey);
                if (ttl > 0 || ttl == -1) {
                    if (contextBindingHash != null) {
                        Object storedHash = redisTemplate.opsForHash().get(analysisKey, "contextBindingHash");
                        return storedHash == null || storedHash.toString().equals(contextBindingHash);
                    }
                    return true;
                }
            }

            return false;

        } catch (Exception e) {
            log.error("[ZeroTrustEventListener] Failed to check skip condition: userId={}", userId, e);
            return false;
        }
    }
}
