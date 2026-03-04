package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;

@Slf4j
public class ZeroTrustEventListener {

    private final SecurityEventPublisher securityEventPublisher;
    private final ZeroTrustActionRepository actionRepository;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;

    public ZeroTrustEventListener(
            SecurityEventPublisher securityEventPublisher,
            ZeroTrustActionRepository actionRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        this.securityEventPublisher = securityEventPublisher;
        this.actionRepository = actionRepository;
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
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processAuthorizationEvent(ZeroTrustSpringEvent event) {
        String userId = event.getUserId();

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(
                event.getSessionId(), event.getClientIp(), event.getUserAgent());
        if (shouldSkipPublishing(userId, contextBindingHash)) {
            return;
        }
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processSessionEvent(ZeroTrustSpringEvent event) {
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processThreatEvent(ZeroTrustSpringEvent event) {
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processCustomEvent(ZeroTrustSpringEvent event) {
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    private boolean shouldSkipPublishing(String userId, String contextBindingHash) {
        if (userId == null || userId.isBlank()) {
            return false;
        }

        try {
            ZeroTrustAction currentAction = actionRepository.getCurrentAction(userId, contextBindingHash);
            return currentAction != ZeroTrustAction.PENDING_ANALYSIS;
        } catch (Exception e) {
            log.error("[ZeroTrustEventListener] Failed to check skip condition: userId={}", userId, e);
            return false;
        }
    }
}
