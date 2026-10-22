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
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.execution.DelegatedExecutionContext;
import io.contexa.contexacore.autonomous.execution.ExecutionSubjectTypes;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** A1-3 (AG-1d): a person, a delegated agent and an autonomous agent are recorded as different subjects. */
class CanonicalExecutionEventMetadataSupportTest {

    @Test
    void aPersonsRequestIsRecordedAsAHumanUser() {
        Map<String, Object> metadata = CanonicalExecutionEventMetadataSupport.enrich(Map.of("userId", "alice"));

        assertThat(metadata).containsEntry("executionSubjectKind", "HUMAN_USER")
                .containsEntry("executionSubjectType", "HUMAN_USER")
                .containsEntry("executionMode", "DIRECT_USER")
                .containsEntry("lineageState", "DIRECT");
    }

    @Test
    void anAgentActingForAPersonIsRecordedAsADelegatedAgent() {
        Map<String, Object> metadata = CanonicalExecutionEventMetadataSupport.enrich(
                Map.of("userId", "alice", "delegated", true, "agentId", "agent-7"));

        assertThat(metadata).containsEntry("executionSubjectKind", "DELEGATED_AGENT")
                .containsEntry("executionSubjectType", "AGENT_RUNTIME")
                .containsEntry("executionMode", "DELEGATED_AGENT")
                .containsEntry("lineageState", "DECLARED");
        assertThat(subject(metadata)).containsEntry("subjectKind", "DELEGATED_AGENT")
                .containsEntry("agentId", "agent-7");
    }

    @Test
    void anAgentActingOnItsOwnIsRecordedAsAnAutonomousAgent() {
        Map<String, Object> metadata = CanonicalExecutionEventMetadataSupport.enrich(
                Map.of("userId", "agent-sp-1", "delegated", false, "agentId", "agent-sp-1"));

        assertThat(metadata).containsEntry("executionSubjectKind", "AUTONOMOUS_AGENT")
                .containsEntry("executionSubjectType", "AGENT_RUNTIME")
                .containsEntry("executionMode", "AUTONOMOUS_AGENT")
                .containsEntry("lineageState", "DIRECT");
    }

    @Test
    void aClientsOwnTokenIsRecordedAsAServiceClient() {
        Map<String, Object> metadata = CanonicalExecutionEventMetadataSupport.enrich(
                Map.of("userId", "report-service", "principalType", "SERVICE_CLIENT"));

        assertThat(metadata).containsEntry("executionSubjectKind", "SERVICE_CLIENT")
                .containsEntry("executionSubjectType", "SERVICE_CLIENT");
    }

    @Test
    void agentFactsOutrankADeclaredPerson() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("executionSubjectType", "HUMAN_USER");
        payload.put("executionMode", "DIRECT_USER");
        payload.put("delegated", true);
        payload.put("agentId", "agent-7");

        Map<String, Object> metadata = CanonicalExecutionEventMetadataSupport.enrich(payload);

        // Before A1-3 the declared values stayed (putIfAbsent) while the subject map said agent.
        assertThat(metadata).containsEntry("executionSubjectType", "AGENT_RUNTIME")
                .containsEntry("executionMode", "DELEGATED_AGENT");
        assertThat(execution(metadata)).containsEntry("executionMode", "DELEGATED_AGENT");
    }

    @Test
    void theSharedKindsCarryTheValuesCoreAlreadyRecords() {
        assertThat(SubjectKind.HUMAN_USER.subjectType()).isEqualTo(ExecutionSubjectTypes.HUMAN_USER);
        assertThat(SubjectKind.SERVICE_CLIENT.subjectType()).isEqualTo(ExecutionSubjectTypes.SERVICE_CLIENT);
        assertThat(SubjectKind.DELEGATED_AGENT.subjectType()).isEqualTo(ExecutionSubjectTypes.AGENT_RUNTIME);
        assertThat(SubjectKind.AUTONOMOUS_AGENT.subjectType()).isEqualTo(ExecutionSubjectTypes.AGENT_RUNTIME);
        assertThat(SubjectKind.HUMAN_USER.executionMode()).isEqualTo(DelegatedExecutionContext.EXECUTION_MODE_DIRECT_USER);
        assertThat(SubjectKind.DELEGATED_AGENT.executionMode())
                .isEqualTo(DelegatedExecutionContext.EXECUTION_MODE_DELEGATED_AGENT);
        assertThat(SubjectKind.AUTONOMOUS_AGENT.executionMode())
                .isEqualTo(DelegatedExecutionContext.EXECUTION_MODE_AUTONOMOUS_AGENT);
        assertThat(SubjectKind.HUMAN_USER.lineageState()).isEqualTo(DelegatedExecutionContext.LINEAGE_STATE_DIRECT);
        assertThat(SubjectKind.DELEGATED_AGENT.lineageState()).isEqualTo(DelegatedExecutionContext.LINEAGE_STATE_DECLARED);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> subject(Map<String, Object> metadata) {
        return (Map<String, Object>) metadata.get("canonicalExecutionSubject");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> execution(Map<String, Object> metadata) {
        return (Map<String, Object>) metadata.get("canonicalExecution");
    }
}
