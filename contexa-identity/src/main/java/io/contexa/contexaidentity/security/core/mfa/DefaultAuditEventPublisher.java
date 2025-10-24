package io.contexa.contexaidentity.security.core.mfa;

import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * AuditEventPublisher 기본 구현: SLF4J 로 이벤트 로깅
 */
@Slf4j
public class DefaultAuditEventPublisher implements AuditEventPublisher {

    @Override
    public void publish(String eventType, Map<String, Object> details) {
        log.info("AUDIT | event={} | details={}", eventType, details);
    }
}