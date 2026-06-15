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
package io.contexa.contexaiam.admin.support.context.service;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserContextServiceImpl")
class UserContextServiceImplTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @InjectMocks
    private UserContextServiceImpl service;

    private AuditLog buildAuditLog(Long id, String username, String action, String resource) {
        return AuditLog.builder()
                .id(id)
                .principalName(username)
                .action(action)
                .resourceIdentifier(resource)
                .timestamp(LocalDateTime.now())
                .build();
    }

    @Nested
    @DisplayName("getRecentActivities")
    class GetRecentActivities {

        @Test
        @DisplayName("should return mapped recent activity list when logs exist")
        void shouldReturnMappedList() {
            String username = "alice";
            AuditLog log1 = buildAuditLog(1L, username, "USER_LOGIN", "system");
            AuditLog log2 = buildAuditLog(2L, username, "POLICY_CREATE", "policy-1");

            when(auditLogRepository.findTop5ByPrincipalNameOrderByIdDesc(username))
                    .thenReturn(List.of(log1, log2));

            List<RecentActivityDto> result = service.getRecentActivities(username);

            assertThat(result).hasSize(2);
            assertThat(result.get(0).action()).isEqualTo("USER_LOGIN");
            assertThat(result.get(0).target()).isEqualTo("system");
            assertThat(result.get(1).action()).isEqualTo("POLICY_CREATE");
            assertThat(result.get(1).target()).isEqualTo("policy-1");

            verify(auditLogRepository).findTop5ByPrincipalNameOrderByIdDesc(username);
        }

        @Test
        @DisplayName("should return empty list when no logs exist for user")
        void shouldReturnEmptyList() {
            String username = "bob";
            when(auditLogRepository.findTop5ByPrincipalNameOrderByIdDesc(username))
                    .thenReturn(Collections.emptyList());

            List<RecentActivityDto> result = service.getRecentActivities(username);

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should handle null or empty username gracefully")
        void shouldHandleNullOrEmptyUsername() {
            when(auditLogRepository.findTop5ByPrincipalNameOrderByIdDesc(null))
                    .thenReturn(Collections.emptyList());

            List<RecentActivityDto> resultNull = service.getRecentActivities(null);
            assertThat(resultNull).isEmpty();

            when(auditLogRepository.findTop5ByPrincipalNameOrderByIdDesc(""))
                    .thenReturn(Collections.emptyList());

            List<RecentActivityDto> resultEmpty = service.getRecentActivities("");
            assertThat(resultEmpty).isEmpty();
        }
    }
}
