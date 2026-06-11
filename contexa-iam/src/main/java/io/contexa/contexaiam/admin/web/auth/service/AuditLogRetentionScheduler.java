/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
    @Transactional(transactionManager = "contexaTransactionManager")
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
