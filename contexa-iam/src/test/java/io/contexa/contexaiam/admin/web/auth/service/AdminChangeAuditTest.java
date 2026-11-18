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
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/** K75: an administrator's change is recorded as the role and user services record theirs, once it is committed. */
class AdminChangeAuditTest {

    private final CentralAuditFacade facade = mock(CentralAuditFacade.class);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    void theChangeIsRecordedWithItsCategoryActionActorAndTarget() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("admin", null, List.of()));
        Map<String, Object> details = new HashMap<>();
        details.put("groupId", 7L);
        details.put("left out", null);

        AdminChangeAudit.of(facade).record(AuditEventCategory.GROUP_UPDATED, "GROUP_UPDATED", "ops", details);

        AuditRecord record = recorded();
        assertThat(record.getEventCategory()).isEqualTo(AuditEventCategory.GROUP_UPDATED);
        assertThat(record.getAction()).isEqualTo("GROUP_UPDATED");
        assertThat(record.getPrincipalName()).isEqualTo("admin");
        assertThat(record.getResourceIdentifier()).isEqualTo("ops");
        assertThat(record.getEventSource()).isEqualTo("IAM");
        assertThat(record.getDecision()).isEqualTo("SUCCESS");
        assertThat(record.getOutcome()).isEqualTo("SUCCESS");
        assertThat(record.getDetails()).containsExactly(Map.entry("groupId", 7L));
    }

    @Test
    void aChangeNoOneSignedInMadeIsTheSystemsAndATargetIsKeptWithinItsColumn() {
        AdminChangeAudit.of(facade).record(AuditEventCategory.MENU_CHANGED, "MENU_REORDERED", null, null);
        assertThat(recorded().getPrincipalName()).isEqualTo("SYSTEM");
        assertThat(recorded().getResourceIdentifier()).isEmpty();

        CentralAuditFacade other = mock(CentralAuditFacade.class);
        AdminChangeAudit.of(other).record(AuditEventCategory.SYSTEM_SETTINGS_CHANGED, "SYSTEM_SETTINGS_CHANGED",
                "x".repeat(600), Map.of());
        ArgumentCaptor<AuditRecord> captor = ArgumentCaptor.forClass(AuditRecord.class);
        verify(other).recordAsync(captor.capture());
        assertThat(captor.getValue().getResourceIdentifier()).hasSize(512);
    }

    @Test
    void inATransactionTheChangeIsRecordedOnceItCommitsAndNotWhenItRollsBack() {
        TransactionSynchronizationManager.initSynchronization();
        AdminChangeAudit audit = AdminChangeAudit.of(facade);
        audit.record(AuditEventCategory.PERMISSION_CREATED, "PERMISSION_CREATED", "REPORT_EXPORT", Map.of());
        audit.record(AuditEventCategory.PERMISSION_DELETED, "PERMISSION_DELETED", "REPORT_OLD", Map.of());

        verify(facade, never()).recordAsync(any());
        List<TransactionSynchronization> pending = TransactionSynchronizationManager.getSynchronizations();
        assertThat(pending).hasSize(2);
        pending.get(0).afterCommit();
        pending.get(1).afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK);

        assertThat(recorded().getResourceIdentifier()).isEqualTo("REPORT_EXPORT");
    }

    @Test
    void withoutTheFacadeNothingIsRecorded() {
        AdminChangeAudit.of(null).record(AuditEventCategory.GROUP_CREATED, "GROUP_CREATED", "ops", Map.of());
        AdminChangeAudit.NONE.record(AuditEventCategory.GROUP_CREATED, "GROUP_CREATED", "ops", Map.of());

        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
    }

    private AuditRecord recorded() {
        ArgumentCaptor<AuditRecord> captor = ArgumentCaptor.forClass(AuditRecord.class);
        verify(facade).recordAsync(captor.capture());
        return captor.getValue();
    }
}
