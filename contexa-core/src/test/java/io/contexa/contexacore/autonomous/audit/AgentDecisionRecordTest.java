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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A5-5: the decision record fields (AG-8) and the request context hash (AG-11l). */
class AgentDecisionRecordTest {

    private static final Instant AT = Instant.parse("2026-10-24T05:00:00Z");

    @Test
    void anAgentsDecisionRecordNamesTheAgentTheDelegatorTheOperationTheRiskAndTheEnforcement() {
        SecurityEvent event = agentExport(AT);
        event.addMetadata(AgentDecisionRecord.ENFORCEMENT_OUTCOME, AgentDecisionRecord.APPLIED);
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("BLOCK")
                .llmDecisionPresent(true)
                .reasonCodes(List.of(new SecurityDecisionOutputContract.Citation("DELEGATION_SCOPE_DRIFT", "F13"),
                        new SecurityDecisionOutputContract.Citation("SESSION_NETWORK_CHANGE", "F12")))
                .build();

        AgentDecisionRecord record = AgentDecisionRecord.of(event, result);

        assertThat(record.subjectKind()).isEqualTo("DELEGATED_AGENT");
        assertThat(record.agentId()).isEqualTo("report-agent");
        assertThat(record.delegatorId()).isEqualTo("alice");
        assertThat(record.delegationId()).isEqualTo("DLG-7");
        assertThat(record.targetAction()).isEqualTo("EXPORT");
        assertThat(record.riskState()).isEqualTo("DELEGATION_SCOPE_DRIFT(F13), SESSION_NETWORK_CHANGE(F12)");
        assertThat(record.enforcementAction()).isEqualTo("BLOCK");
        assertThat(record.enforcementCause()).isEqualTo("MODEL_DECISION");
        assertThat(record.requestContextHash()).hasSize(64).isEqualTo(AgentDecisionRecord.requestContextHash(event));
    }

    @Test
    void aPersonsRecordNamesNoAgentAndAKeptOrObservedDecisionSaysSo() {
        SecurityEvent person = event("alice", Map.of("executionSubjectKind", "HUMAN_USER", "actionFamily", "READ",
                "agentId", "report-agent", AgentDecisionRecord.ENFORCEMENT_OUTCOME, AgentDecisionRecord.KEPT_STRICTER),
                AT);
        ProcessingResult fallback = ProcessingResult.builder().success(true).action("ESCALATE")
                .technicalFallbackApplied(true).technicalFallbackReason("model timed out").build();

        AgentDecisionRecord record = AgentDecisionRecord.of(person, fallback);

        assertThat(record.agentId()).isNull();
        assertThat(record.delegatorId()).isNull();
        assertThat(record.delegationId()).isNull();
        assertThat(record.targetAction()).isEqualTo("READ");
        assertThat(record.enforcementAction()).isEqualTo(AgentDecisionRecord.KEPT_STRICTER);
        assertThat(record.enforcementCause()).isEqualTo("TECHNICAL_FALLBACK: model timed out");
        assertThat(record.riskState()).isNull();
    }

    @Test
    void theContextHashChangesWithTheTimeAndTheContentHashMatchesTheSameRequestSentAgain() {
        SecurityEvent first = agentExport(AT);
        SecurityEvent again = agentExport(AT.plusSeconds(300));
        SecurityEvent other = agentExport(AT);
        other.addMetadata("requestItems", 400);

        assertThat(AgentDecisionRecord.requestContextHash(again))
                .isNotEqualTo(AgentDecisionRecord.requestContextHash(first));
        assertThat(AgentDecisionRecord.requestContentHash(again))
                .isEqualTo(AgentDecisionRecord.requestContentHash(first));
        assertThat(AgentDecisionRecord.requestContentHash(other))
                .isNotEqualTo(AgentDecisionRecord.requestContentHash(first));
        assertThat(AgentDecisionRecord.requestContextHash(first))
                .as("stable for the same request").isEqualTo(AgentDecisionRecord.requestContextHash(agentExport(AT)));
    }

    private static SecurityEvent agentExport(Instant at) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("executionSubjectKind", "DELEGATED_AGENT");
        metadata.put("agentId", "report-agent");
        metadata.put("delegationId", "DLG-7");
        metadata.put("delegatorId", "alice");
        metadata.put("tenantId", "tenant-a");
        metadata.put("actionFamily", "EXPORT");
        metadata.put("httpMethod", "POST");
        metadata.put("requestPath", "/api/projects/GB-500/exports");
        metadata.put("resourceId", "GB-500");
        metadata.put("requestItems", 40);
        return event("alice", metadata, at);
    }

    private static SecurityEvent event(String userId, Map<String, Object> metadata, Instant at) {
        SecurityEvent event = new SecurityEvent();
        event.setUserId(userId);
        event.setTimestamp(at);
        event.setMetadata(new HashMap<>(metadata));
        return event;
    }
}
