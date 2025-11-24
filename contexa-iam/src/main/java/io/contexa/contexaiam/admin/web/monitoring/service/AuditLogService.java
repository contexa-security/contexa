package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    @Async // 이 메서드는 별도의 스레드에서 비동기적으로 실행됨
    @Transactional
    public void logDecision(String principal, String resource, String action, String decision, String reason, String clientIp) {
        try {
            AuditLog logEntry = AuditLog.builder()
                    .principalName(principal)
                    .resourceIdentifier(resource)
                    .action(action)
                    .decision(decision)
                    .reason(reason)
                    .clientIp(clientIp)
                    .build();
            auditLogRepository.save(logEntry);
        } catch (Exception e) {
            log.error("Failed to save audit log", e);
        }
    }
}