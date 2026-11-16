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
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Plan 3.7: what is done to a version is a record of the console's audit log in the form the history table of the
 * version screens reads: the action named by {@link PromptVersionAudit}, the prompt version category, the actor (else
 * {@code system}), the resource {@code {prompt}@{version}}, the detail as the reason and in the details, and RECORDED as
 * the decision and the outcome.
 */
class AuditLogPromptVersionAuditTest {

    @Test
    void aVersionActionIsARecordOfTheAuditLogTheVersionScreensRead() {
        CentralAuditFacade facade = mock(CentralAuditFacade.class);
        PromptVersionAudit audit = new AuditLogPromptVersionAudit(facade);

        audit.record(PromptVersionAudit.USED_FOR_DECISIONS, "PLATFORM_GLOBAL", "cortex.security-decision", "v2.0",
                "admin", "month-end closing");
        audit.record(PromptVersionAudit.CREATED, "PLATFORM_GLOBAL", "cortex.security-decision", "v1.0", null, null);

        ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
        verify(facade, times(2)).recordAsync(records.capture());
        AuditLog used = records.getAllValues().get(0).toAuditLog("{}");
        assertThat(List.of(used.getAction(), used.getEventCategory(), used.getPrincipalName(),
                used.getResourceIdentifier(), used.getReason(), used.getDecision(), used.getOutcome(),
                used.getEventSource())).containsExactly("PROMPT_VERSION_USED_FOR_DECISIONS",
                AuditEventCategory.PROMPT_VERSION_CHANGED.name(), "admin", "cortex.security-decision@v2.0",
                "month-end closing", "RECORDED", "RECORDED", "IAM");
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("scope", "PLATFORM_GLOBAL");
        details.put("prompt", "cortex.security-decision");
        details.put("version", "v2.0");
        details.put("detail", "month-end closing");
        assertThat(records.getAllValues().get(0).getDetails()).containsExactlyEntriesOf(details);

        AuditLog made = records.getAllValues().get(1).toAuditLog("{}");
        assertThat(made.getPrincipalName()).isEqualTo("system");
        assertThat(made.getReason()).isNull();
        assertThat(made.getDecision()).isEqualTo("RECORDED");
        assertThat(records.getAllValues().get(1).getDetails()).containsEntry("detail", null);
    }

    @Test
    void theConstantsAreTheNamesTheVersionScreensRead() {
        assertThat(List.of(PromptVersionAudit.CANARY_STARTED, PromptVersionAudit.CANARY_STOPPED,
                PromptVersionAudit.SHADOW_STARTED, PromptVersionAudit.SHADOW_STOPPED,
                PromptVersionAudit.EMERGENCY_ROLLBACK, PromptVersionAudit.ROLLBACK_APPROVED,
                PromptVersionAudit.TRIAL_STARTED, PromptVersionAudit.TRIAL_CANCELLED)).containsExactly(
                "PROMPT_VERSION_CANARY_STARTED", "PROMPT_VERSION_CANARY_STOPPED", "PROMPT_VERSION_SHADOW_STARTED",
                "PROMPT_VERSION_SHADOW_STOPPED", "PROMPT_VERSION_EMERGENCY_ROLLBACK", "PROMPT_VERSION_ROLLBACK_APPROVED",
                "PROMPT_VERSION_TRIAL_STARTED", "PROMPT_VERSION_TRIAL_CANCELLED");
    }

    @Test
    void aRecordThatCannotBeHandedOverDoesNotUndoTheAction() {
        CentralAuditFacade facade = mock(CentralAuditFacade.class);
        doThrow(new IllegalStateException("closed")).when(facade).recordAsync(any());

        assertThatCode(() -> new AuditLogPromptVersionAudit(facade).record(PromptVersionAudit.HIDDEN,
                "PLATFORM_GLOBAL", "cortex.security-decision", "v3.0", "admin", null)).doesNotThrowAnyException();
    }
}
