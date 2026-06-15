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

import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacommon.repository.AuditLogRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuditLogRetentionScheduler")
class AuditLogRetentionSchedulerTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private SystemSettingsService systemSettingsService;

    @InjectMocks
    private AuditLogRetentionScheduler scheduler;

    @Test
    @DisplayName("should skip cleanup when retention days is zero or negative")
    void skipCleanup() {
        SystemSettings settings = SystemSettings.builder()
                .auditLogRetentionDays(0)
                .build();
        when(systemSettingsService.getSettings()).thenReturn(settings);

        scheduler.cleanupExpiredAuditLogs();

        verifyNoInteractions(auditLogRepository);
    }

    @Test
    @DisplayName("should call deleteByTimestampBefore when retention days is positive")
    void performCleanup() {
        SystemSettings settings = SystemSettings.builder()
                .auditLogRetentionDays(30)
                .build();
        when(systemSettingsService.getSettings()).thenReturn(settings);
        when(auditLogRepository.deleteByTimestampBefore(any(LocalDateTime.class))).thenReturn(5);

        scheduler.cleanupExpiredAuditLogs();

        verify(auditLogRepository).deleteByTimestampBefore(argThat(time ->
                time.isBefore(LocalDateTime.now().minusDays(29).minusHours(23)) &&
                time.isAfter(LocalDateTime.now().minusDays(30).minusMinutes(5))
        ));
    }
}
