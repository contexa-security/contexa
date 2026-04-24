package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Scheduled task to clean up audit logs based on retention policy.
 */
@Slf4j
@RequiredArgsConstructor
public class AuditLogRetentionScheduler {

    private final AuditLogRepository auditLogRepository;
    private final SystemSettingsService systemSettingsService;

    @Scheduled(cron = "0 0 2 * * *")
    @SchedulerLock(name = "auditLogRetentionCleanup", lockAtMostFor = "PT30M", lockAtLeastFor = "PT1M")
    @Transactional
    public void cleanupExpiredAuditLogs() {
        int retentionDays = systemSettingsService.getSettings().getAuditLogRetentionDays();
        if (retentionDays <= 0) {
            return;
        }

        LocalDateTime cutoff = LocalDateTime.now().minusDays(retentionDays);
        int deleted = auditLogRepository.deleteByTimestampBefore(cutoff);
        if (deleted > 0) {
            log.error("Audit log retention: deleted {} records older than {} days (before {})",
                    deleted, retentionDays, cutoff);
        }
    }
}
