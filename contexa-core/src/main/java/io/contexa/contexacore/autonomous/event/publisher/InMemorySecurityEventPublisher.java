package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.InMemorySecurityEventCollector;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * In-memory implementation of SecurityEventPublisher for standalone mode.
 * Dispatches events directly to InMemorySecurityEventCollector without Kafka.
 */
@Slf4j
@RequiredArgsConstructor
public class InMemorySecurityEventPublisher implements SecurityEventPublisher {

    private final SecurityEventCollector eventCollector;

    @Override
    public void publishGenericSecurityEvent(ZeroTrustSpringEvent event) {
        if (event == null) {
            return;
        }

        try {
            SecurityEvent securityEvent = convertToSecurityEvent(event);

            if (eventCollector instanceof InMemorySecurityEventCollector inMemoryCollector) {
                inMemoryCollector.dispatchEvent(securityEvent);
            }
        } catch (Exception e) {
            log.error("Failed to publish in-memory security event: userId={}", event.getUserId(), e);
        }
    }

    private SecurityEvent convertToSecurityEvent(ZeroTrustSpringEvent event) {
        SecurityEvent securityEvent = new SecurityEvent();
        securityEvent.setEventId(UUID.randomUUID().toString());
        securityEvent.setTimestamp(LocalDateTime.now());
        securityEvent.setUserId(event.getUserId());
        securityEvent.setSessionId(event.getSessionId());
        securityEvent.setSourceIp(event.getClientIp());
        securityEvent.setUserAgent(event.getUserAgent());
        securityEvent.setSource(SecurityEvent.EventSource.IAM);
        securityEvent.setDescription(event.getFullEventType());

        Map<String, Object> payload = event.getPayload();
        if (payload != null) {
            securityEvent.setSeverity(determineSeverity(payload));
            payload.forEach((key, value) -> {
                if (value != null) {
                    securityEvent.addMetadata(key, value);
                }
            });
        } else {
            securityEvent.setSeverity(SecurityEvent.Severity.LOW);
        }

        return securityEvent;
    }

    private SecurityEvent.Severity determineSeverity(Map<String, Object> payload) {
        Object actionObj = payload.get("action");
        if (actionObj != null) {
            try {
                ZeroTrustAction action = ZeroTrustAction.fromString(actionObj.toString());
                return switch (action) {
                    case BLOCK -> SecurityEvent.Severity.CRITICAL;
                    case ESCALATE -> SecurityEvent.Severity.HIGH;
                    case CHALLENGE, PENDING_ANALYSIS -> SecurityEvent.Severity.MEDIUM;
                    case ALLOW -> SecurityEvent.Severity.LOW;
                };
            } catch (Exception ignored) {
                // fall through to default
            }
        }
        return SecurityEvent.Severity.LOW;
    }
}
