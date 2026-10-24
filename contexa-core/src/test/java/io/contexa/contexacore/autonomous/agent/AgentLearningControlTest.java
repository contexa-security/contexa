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
package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * docs/agent A3-8 (AG-11j): an administrator quarantines, releases or removes what an agent, or one of its delegations,
 * learned; the learning of people and of other agents stays.
 */
class AgentLearningControlTest {

    private final InMemorySecurityContextDataStore contextStore = new InMemorySecurityContextDataStore();
    private final InMemoryBaselineDataStore baselineStore = new InMemoryBaselineDataStore(Duration.ofDays(30));
    private final PastRecordQuery records = mock(PastRecordQuery.class);
    private final AgentLearningControl control = new AgentLearningControl(contextStore, baselineStore, () -> records);
    private BaselineLearningService learning;

    @BeforeEach
    void setUp() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        SecurityZeroTrustProperties.BaselineSettings baseline = new SecurityZeroTrustProperties.BaselineSettings();
        SecurityZeroTrustProperties.BaselineSettings.LearningSettings settings =
                new SecurityZeroTrustProperties.BaselineSettings.LearningSettings();
        settings.setEnabled(true);
        baseline.setLearning(settings);
        properties.setBaseline(baseline);
        learning = new BaselineLearningService(baselineStore, properties);
        learning.setLearningQuarantine(subject -> AgentLearningControl.learningQuarantined(contextStore, subject));
    }

    @Test
    void aQuarantinedAgentNeitherLearnsNorIsReadUntilTheRelease() {
        when(records.quarantineAgentRecords("agt-1", null)).thenReturn(3);
        when(records.releaseAgentRecords(any(), any(), any())).thenReturn(3);
        learning.learnIfNormal("alice", allow(), agentEvent("agt-1", null));

        AgentLearningControl.Outcome quarantined = control.quarantine(" agt-1 ", null);

        assertThat(quarantined).isEqualTo(new AgentLearningControl.Outcome("QUARANTINE", "agt-1", null, 3, 0, 0));
        assertThat(control.quarantined("agt-1", null)).isTrue();
        assertThat(learning.getPersonalBaseline("alice", agentEvent("agt-1", null))).isNull();
        assertThat(learning.learnIfNormal("alice", allow(), agentEvent("agt-1", null))).isFalse();
        // The person and another agent learn and are read as before.
        assertThat(learning.learnIfNormal("alice", allow(), personEvent())).isTrue();
        assertThat(learning.learnIfNormal("alice", allow(), agentEvent("agt-2", null))).isTrue();
        assertThat(learning.getPersonalBaseline("alice", agentEvent("agt-2", null))).isNotNull();

        AgentLearningControl.Outcome released = control.release("agt-1", null);

        assertThat(released.records()).isEqualTo(3);
        assertThat(control.quarantined("agt-1", null)).isFalse();
        assertThat(learning.getPersonalBaseline("alice", agentEvent("agt-1", null)).getUpdateCount()).isEqualTo(1L);
        assertThat(learning.learnIfNormal("alice", allow(), agentEvent("agt-1", null))).isTrue();
    }

    /**
     * A delegation's learning is its decision records: they are quarantined, those it has and those its requests make,
     * and the agent's baseline (kept per agent) goes on.
     */
    @Test
    void aQuarantinedDelegationQuarantinesItsRecordsOnly() {
        control.quarantine("agt-1", "dlg-1");

        assertThat(control.quarantined("agt-1", "dlg-1")).isTrue();
        assertThat(control.quarantined("agt-1", null)).isFalse();
        verify(records).quarantineAgentRecords("agt-1", "dlg-1");
        assertThat(AgentLearningControl.recordsQuarantined(contextStore,
                LearningSubject.of(agentEvent("agt-1", "dlg-1")))).isTrue();
        assertThat(AgentLearningControl.recordsQuarantined(contextStore,
                LearningSubject.of(agentEvent("agt-1", "dlg-2")))).isFalse();
        assertThat(AgentLearningControl.learningQuarantined(contextStore,
                LearningSubject.of(agentEvent("agt-1", "dlg-1")))).isFalse();
        assertThat(learning.learnIfNormal("alice", allow(), agentEvent("agt-1", "dlg-1"))).isTrue();
    }

    @Test
    void releasingTheAgentKeepsTheRecordsOfItsDelegationsStillQuarantined() {
        control.quarantine("agt-1", "dlg-1");
        control.quarantine("agt-1", null);

        control.release("agt-1", null);

        verify(records).releaseAgentRecords("agt-1", null, List.of("dlg-1"));
        assertThat(control.quarantined("agt-1", "dlg-1")).isTrue();
        assertThat(AgentLearningControl.recordsQuarantined(contextStore,
                LearningSubject.of(agentEvent("agt-1", "dlg-1")))).isTrue();
        assertThat(learning.learnIfNormal("alice", allow(), agentEvent("agt-1", "dlg-1"))).isTrue();
    }

    @Test
    void releasingADelegationOfAnAgentStillQuarantinedChangesNoRecord() {
        control.quarantine("agt-1", null);
        control.quarantine("agt-1", "dlg-1");

        AgentLearningControl.Outcome released = control.release("agt-1", "dlg-1");

        assertThat(released.records()).isZero();
        verify(records, never()).releaseAgentRecords(anyString(), anyString(), any());
        assertThat(control.quarantined("agt-1", "dlg-1")).isFalse();
        assertThat(control.quarantined("agt-1", null)).isTrue();
    }

    @Test
    void removingTheAgentRemovesItsBaselinesObservationsAndRecordsInEveryTenantOnly() {
        when(records.removeAgentRecords("agt-1", null)).thenReturn(4);
        baselineStore.saveUserBaseline("t-1::alice::agent::agt-1", baseline("alice"));
        baselineStore.saveUserBaseline("bob::agent::agt-1", baseline("bob"));
        baselineStore.saveUserBaseline("alice::agent::agt-2", baseline("alice"));
        baselineStore.saveUserBaseline("alice", baseline("alice"));
        contextStore.addWorkProfileObservation("t-1", LearningSubject.agentKey("alice", "agt-1"), "{}");
        contextStore.addWorkProfileObservation(null, LearningSubject.agentKey("bob", "agt-1"), "{}");
        contextStore.addWorkProfileObservation(null, LearningSubject.agentKey("alice", "agt-2"), "{}");
        contextStore.addWorkProfileObservation(null, "alice", "{}");

        AgentLearningControl.Outcome removed = control.remove("agt-1", null);

        assertThat(removed).isEqualTo(new AgentLearningControl.Outcome("REMOVE", "agt-1", null, 4, 2, 2));
        assertThat(baselineStore.getUserBaseline("t-1::alice::agent::agt-1")).isNull();
        assertThat(baselineStore.getUserBaseline("bob::agent::agt-1")).isNull();
        assertThat(baselineStore.getUserBaseline("alice::agent::agt-2")).isNotNull();
        assertThat(baselineStore.getUserBaseline("alice")).isNotNull();
        assertThat(contextStore.getRecentWorkProfileObservations("t-1", LearningSubject.agentKey("alice", "agt-1"), 5))
                .isEmpty();
        assertThat(contextStore.getRecentWorkProfileObservations(null, LearningSubject.agentKey("alice", "agt-2"), 5))
                .hasSize(1);
        assertThat(contextStore.getRecentWorkProfileObservations(null, "alice", 5)).hasSize(1);
    }

    @Test
    void removingADelegationRemovesItsRecordsOnly() {
        when(records.removeAgentRecords("agt-1", "dlg-1")).thenReturn(2);
        baselineStore.saveUserBaseline("alice::agent::agt-1", baseline("alice"));

        AgentLearningControl.Outcome removed = control.remove("agt-1", "dlg-1");

        assertThat(removed).isEqualTo(new AgentLearningControl.Outcome("REMOVE", "agt-1", "dlg-1", 2, 0, 0));
        assertThat(baselineStore.getUserBaseline("alice::agent::agt-1")).isNotNull();
    }

    @Test
    void anAgentIsRequiredAndAQuarantineNeedsAStoreThatKeepsIt() {
        AgentLearningControl withoutStore = new AgentLearningControl(null, null, null);

        assertThatThrownBy(() -> control.quarantine(" ", null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> withoutStore.quarantine("agt-1", null)).isInstanceOf(IllegalStateException.class);
        assertThat(withoutStore.quarantined("agt-1", null)).isFalse();
        assertThat(AgentLearningControl.learningQuarantined(null, LearningSubject.of(agentEvent("agt-1", null))))
                .isFalse();
        assertThat(AgentLearningControl.recordsQuarantined(null, LearningSubject.of(agentEvent("agt-1", "dlg-1"))))
                .isFalse();
        // A person's learning is never quarantined here.
        contextStore.setLearningQuarantined("agent:alice", true);
        assertThat(AgentLearningControl.learningQuarantined(contextStore, LearningSubject.of(personEvent()))).isFalse();
        assertThat(AgentLearningControl.recordsQuarantined(contextStore, LearningSubject.of(personEvent()))).isFalse();
    }

    private static SecurityEvent agentEvent(String agentId, String delegationId) {
        SecurityEvent event = personEvent();
        event.addMetadata("executionSubjectKind", "DELEGATED_AGENT");
        event.addMetadata("agentId", agentId);
        if (delegationId != null) {
            event.addMetadata("delegationId", delegationId);
        }
        return event;
    }

    private static SecurityEvent personEvent() {
        return SecurityEvent.builder()
                .userId("alice")
                .sourceIp("10.0.0.1")
                .timestamp(Instant.now())
                .build();
    }

    private static BaselineVector baseline(String userId) {
        return BaselineVector.builder().userId(userId).updateCount(3L).avgTrustScore(0.9).build();
    }

    private static SecurityDecision allow() {
        return SecurityDecision.builder().action(ZeroTrustAction.ALLOW).riskScore(0.1).confidence(1.0).build();
    }
}
