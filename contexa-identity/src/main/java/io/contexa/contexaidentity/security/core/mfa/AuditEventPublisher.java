package io.contexa.contexaidentity.security.core.mfa;

import java.util.Map;

/**
 * MFA 감사 이벤트 발행기 인터페이스
 */
public interface AuditEventPublisher {
    void publish(String eventType, Map<String, Object> details);
}

