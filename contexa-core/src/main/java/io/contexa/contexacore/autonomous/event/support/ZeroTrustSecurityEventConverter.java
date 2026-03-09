package io.contexa.contexacore.autonomous.event.support;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Map;
import java.util.UUID;

public final class ZeroTrustSecurityEventConverter {

    private ZeroTrustSecurityEventConverter() {
    }

    public static SecurityEvent convert(ZeroTrustSpringEvent zeroTrustEvent) {
        Map<String, Object> payload = zeroTrustEvent.getPayload();

        String eventId = payload != null && payload.get("eventId") != null
                ? String.valueOf(payload.get("eventId"))
                : UUID.randomUUID().toString();

        String userName = payload != null && payload.get("userName") != null
                ? String.valueOf(payload.get("userName"))
                : null;

        String description = payload != null && payload.get("description") != null
                ? String.valueOf(payload.get("description"))
                : zeroTrustEvent.getCategory() + " event: " + zeroTrustEvent.getEventType();

        SecurityEvent event = SecurityEvent.builder()
                .eventId(eventId)
                .source(SecurityEvent.EventSource.IAM)
                .severity(determineSeverityFromPayload(payload))
                .timestamp(LocalDateTime.ofInstant(zeroTrustEvent.getEventTimestamp(), ZoneId.systemDefault()))
                .description(description)
                .userId(zeroTrustEvent.getUserId())
                .userName(userName)
                .sourceIp(zeroTrustEvent.getClientIp())
                .sessionId(zeroTrustEvent.getSessionId())
                .userAgent(zeroTrustEvent.getUserAgent())
                .build();

        if (payload != null) {
            payload.forEach((key, value) -> {
                if (value != null && !"eventId".equals(key) && !"userName".equals(key) && !"description".equals(key)) {
                    event.addMetadata(key, value);
                }
            });
        }

        if (zeroTrustEvent.getResource() != null) {
            event.addMetadata("requestPath", zeroTrustEvent.getResource());
        }

        return event;
    }

    private static SecurityEvent.Severity determineSeverityFromPayload(Map<String, Object> payload) {
        if (payload == null) {
            return SecurityEvent.Severity.MEDIUM;
        }

        Object actionValue = payload.get("action");
        if (actionValue != null) {
            return mapActionToSeverity(actionValue.toString());
        }

        Object failureCount = payload.get("failureCount");
        if (failureCount != null) {
            int count = parseIntSafely(failureCount);
            if (count > 10) {
                return SecurityEvent.Severity.HIGH;
            }
            if (count > 5) {
                return SecurityEvent.Severity.MEDIUM;
            }
        }

        Object granted = payload.get("granted");
        if (granted != null && !Boolean.parseBoolean(granted.toString())) {
            return SecurityEvent.Severity.MEDIUM;
        }

        if (payload.get("failureReason") != null) {
            return SecurityEvent.Severity.MEDIUM;
        }

        return SecurityEvent.Severity.LOW;
    }

    private static SecurityEvent.Severity mapActionToSeverity(String actionStr) {
        ZeroTrustAction action = ZeroTrustAction.fromString(actionStr);
        return switch (action) {
            case BLOCK -> SecurityEvent.Severity.CRITICAL;
            case ESCALATE -> SecurityEvent.Severity.HIGH;
            case CHALLENGE, PENDING_ANALYSIS -> SecurityEvent.Severity.MEDIUM;
            case ALLOW -> SecurityEvent.Severity.LOW;
        };
    }

    private static int parseIntSafely(Object value) {
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
