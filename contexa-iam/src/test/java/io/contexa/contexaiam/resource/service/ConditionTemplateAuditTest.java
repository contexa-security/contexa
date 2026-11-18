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
package io.contexa.contexaiam.resource.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** K130: a classification of a condition template is audited with its values before and after; one as it was not. */
class ConditionTemplateAuditTest {

    @Test
    void aClassificationIsAuditedWithItsValuesAndOneAsItWasIsNot() {
        CentralAuditFacade facade = mock(CentralAuditFacade.class);
        ConditionTemplateAudit audit = ConditionTemplateAudit.of(facade);
        ConditionTemplate condition = new ConditionTemplate();
        condition.setName("Working hours");
        condition.setApprovalRequired(false);
        ConditionTemplateAudit.Classification before = ConditionTemplateAudit.Classification.of(condition);

        audit.classified(7L, before, condition);
        condition.setApprovalRequired(true);
        audit.classified(7L, before, condition);
        audit.generated("CONDITION_TEMPLATES_GENERATED", List.of(condition, condition));

        ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
        verify(facade, times(2)).recordAsync(records.capture());
        AuditRecord classified = records.getAllValues().get(0);
        assertThat(classified.getEventCategory()).isEqualTo(AuditEventCategory.CONDITION_TEMPLATE_CHANGED);
        assertThat(classified.getAction()).isEqualTo("CONDITION_CLASSIFIED");
        assertThat(classified.getResourceIdentifier()).isEqualTo("Working hours");
        assertThat(classified.getDetails()).containsEntry("conditionId", 7L);
        assertThat(((Map<?, ?>) classified.getDetails().get("before")).get("approvalRequired")).isEqualTo(false);
        assertThat(((Map<?, ?>) classified.getDetails().get("after")).get("approvalRequired")).isEqualTo(true);
        assertThat(records.getAllValues().get(1).getAction()).isEqualTo("CONDITION_TEMPLATES_GENERATED");
        assertThat(records.getAllValues().get(1).getDetails()).containsEntry("generated", 2);
    }
}
