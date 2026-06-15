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

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.soar.event.SecurityActionEvent;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("BlockedUserTimeoutScheduler")
class BlockedUserTimeoutSchedulerTest {

    @Mock
    private BlockedUserJpaRepository blockedUserJpaRepository;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Mock
    private CentralAuditFacade centralAuditFacade;

    @InjectMocks
    private BlockedUserTimeoutScheduler scheduler;

    @Test
    @DisplayName("should do nothing when there are no timed out blocked users")
    void noTimedOutUsers() {
        when(blockedUserJpaRepository.findByStatusAndBlockedAtBefore(eq(BlockedUserStatus.BLOCKED), any(LocalDateTime.class)))
                .thenReturn(Collections.emptyList());

        scheduler.checkBlockedUserTimeout();

        verifyNoInteractions(eventPublisher, centralAuditFacade);
        verify(blockedUserJpaRepository, never()).save(any(BlockedUser.class));
    }

    @Test
    @DisplayName("should publish events, update statuses, and log audits for timed out users")
    void timedOutUsersExist() {
        LocalDateTime blockedAt = LocalDateTime.now().minusHours(25);
        BlockedUser user = BlockedUser.builder()
                .id(1L)
                .userId("target-user")
                .sourceIp("192.168.1.100")
                .requestId("req-123")
                .riskScore(75.5)
                .blockedAt(blockedAt)
                .status(BlockedUserStatus.BLOCKED)
                .build();

        when(blockedUserJpaRepository.findByStatusAndBlockedAtBefore(eq(BlockedUserStatus.BLOCKED), any(LocalDateTime.class)))
                .thenReturn(List.of(user));

        scheduler.checkBlockedUserTimeout();

        // 1. Verify Event Published
        ArgumentCaptor<SecurityActionEvent> eventCaptor = ArgumentCaptor.forClass(SecurityActionEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        SecurityActionEvent publishedEvent = eventCaptor.getValue();
        assertThat(publishedEvent.getUserId()).isEqualTo("target-user");
        assertThat(publishedEvent.getSourceIp()).isEqualTo("192.168.1.100");
        assertThat(publishedEvent.getActionType()).isEqualTo(SecurityActionEvent.ActionType.SOAR_AUTO_RESPONSE);
        assertThat(publishedEvent.getMetadata().get("incidentId")).isEqualTo("req-123");

        // 2. Verify Status Update Saved
        assertThat(user.getStatus()).isEqualTo(BlockedUserStatus.TIMEOUT_RESPONDED);
        verify(blockedUserJpaRepository).save(user);

        // 3. Verify Central Audit Recorded
        ArgumentCaptor<AuditRecord> auditCaptor = ArgumentCaptor.forClass(AuditRecord.class);
        verify(centralAuditFacade).recordAsync(auditCaptor.capture());
        AuditRecord record = auditCaptor.getValue();
        assertThat(record.getEventCategory()).isEqualTo(AuditEventCategory.SOAR_AUTO_RESPONSE);
        assertThat(record.getPrincipalName()).isEqualTo("target-user");
        assertThat(record.getClientIp()).isEqualTo("192.168.1.100");
        assertThat(record.getOutcome()).isEqualTo("AUTO_BLOCKED");
        assertThat(record.getRiskScore()).isEqualTo(75.5);
    }
}
