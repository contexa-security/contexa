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
package io.contexa.contexacore.autonomous.audit;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.store.ContexaStores;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class UndecidedCallsAuditTest {

    @Test
    @DisplayName("Q-7: the interval without decisions is on the audit log, with how many calls passed in it")
    void theIntervalIsOnTheAuditLog() {
        CentralAuditFacade audit = mock(CentralAuditFacade.class);
        Instant from = Instant.parse("2026-11-05T10:00:00Z");
        Instant to = Instant.parse("2026-11-05T10:03:00Z");

        new UndecidedCallsAudit(audit).accept(new ContexaStores.UndecidedCalls(from, to, 41));

        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(record.capture());
        assertThat(record.getValue().getEventCategory()).isEqualTo(AuditEventCategory.SECURITY_ERROR);
        assertThat(record.getValue().getDecision()).isEqualTo("NO_DECISION");
        assertThat(record.getValue().getReason()).contains("41 protected calls").contains(from.toString()).contains(to.toString());
        assertThat(record.getValue().getDetails()).containsEntry("calls", 41L)
                .containsEntry("from", from.toString()).containsEntry("to", to.toString());
    }
}
