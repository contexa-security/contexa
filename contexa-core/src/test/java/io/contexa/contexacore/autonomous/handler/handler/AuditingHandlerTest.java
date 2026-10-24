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
package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.audit.AgentDecisionRecord;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** docs/agent A5-5: the decision record an agent request leaves. */
class AuditingHandlerTest {

    @Test
    void anAgentsDecisionLeavesTheDecisionRecordFieldsAndItsCorrelation() {
        CentralAuditFacade facade = mock(CentralAuditFacade.class);
        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .timestamp(Instant.parse("2026-10-24T05:00:00Z"))
                .build();
        event.addMetadata("executionSubjectKind", "DELEGATED_AGENT");
        event.addMetadata("agentId", "report-agent");
        event.addMetadata("delegatorId", "alice");
        event.addMetadata("delegationId", "DLG-7");
        event.addMetadata("actionFamily", "EXPORT");
        event.addMetadata("requestId", "request-9");
        event.addMetadata(AgentDecisionRecord.ENFORCEMENT_OUTCOME, AgentDecisionRecord.APPLIED);
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event).build();
        // The pipeline measures the response before the decision is audited.
        context.getProcessingMetrics().setResponseTimeMs(42L);
        context.addMetadata("processingResult", ProcessingResult.builder()
                .success(true)
                .action("BLOCK")
                .riskScore(0.97)
                .reasoning("Export outside the delegation")
                .reasonCodes(List.of(new SecurityDecisionOutputContract.Citation("DELEGATION_SCOPE_DRIFT", "F13")))
                .build());

        new AuditingHandler(facade).handle(context);

        ArgumentCaptor<AuditRecord> captor = ArgumentCaptor.forClass(AuditRecord.class);
        verify(facade).recordSync(captor.capture());
        AuditLog row = captor.getValue().toAuditLog(null);
        assertThat(row.getDecision()).isEqualTo("BLOCK");
        assertThat(row.getCorrelationId()).isEqualTo("request-9");
        assertThat(row.getSubjectKind()).isEqualTo("DELEGATED_AGENT");
        assertThat(row.getAgentId()).isEqualTo("report-agent");
        assertThat(row.getDelegatorId()).isEqualTo("alice");
        assertThat(row.getDelegationId()).isEqualTo("DLG-7");
        assertThat(row.getTargetAction()).isEqualTo("EXPORT");
        assertThat(row.getRiskState()).isEqualTo("DELEGATION_SCOPE_DRIFT(F13)");
        assertThat(row.getEnforcementAction()).isEqualTo("BLOCK");
        assertThat(row.getRequestContextHash()).isEqualTo(AgentDecisionRecord.requestContextHash(event));
    }
}
