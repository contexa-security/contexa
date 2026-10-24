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
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.CredentialFacts;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * docs/agent A5-3: a BLOCK stops the agent only. Acting for a person, its delegation and the tokens its client holds
 * for that person are revoked and the person is told; acting on its own, it is suspended, its tokens are revoked and
 * its sponsor is told. The person's own work and other agents are not touched.
 */
class AgentContainmentServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-24T01:00:00Z");

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry(Clock.fixed(NOW, ZoneOffset.UTC));
    private final InMemoryDelegationRegistry delegations = new InMemoryDelegationRegistry(Duration.ofDays(30),
            Clock.fixed(NOW, ZoneOffset.UTC));
    private final List<String> revoked = new ArrayList<>();
    private final InMemoryAgentNoticeStore noticeStore = new InMemoryAgentNoticeStore();
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final AgentContainmentService containment = new AgentContainmentService(actions, registry, delegations,
            (principal, clientId) -> {
                revoked.add(principal + "/" + clientId);
                return 2;
            },
            new AgentNotices(noticeStore, notice -> "MAIL", Clock.fixed(NOW, ZoneOffset.UTC)), audit);

    @Test
    void aBlockOfAnAgentActingForAPersonRevokesItsDelegationAndTokensAndTellsThePerson() {
        registry.register(new AgentRegistrationRequest(null, "report-agent", "Report", null, "report-client",
                "carol", true));
        AgentDelegation delegation = delegations.record(new AgentDelegationRequest(null, "alice", "report-agent", null,
                "REPORTING", "Prepare the weekly HX-310 drawing report", List.of("READ"), List.of("HX-310"), null,
                null, null, NOW.minusSeconds(3600), NOW.plus(Duration.ofDays(3)), null, null));
        actions.saveAction("alice", ZeroTrustAction.ALLOW, Map.of());
        SecurityEvent event = SecurityEvent.builder().userId("alice").build();
        event.addMetadata("executionSubjectKind", "DELEGATED_AGENT");
        event.addMetadata("agentId", "report-agent");
        event.addMetadata("delegationId", delegation.delegationId());
        event.addMetadata(CredentialFacts.CLIENT_ID, "report-client");
        event.addMetadata("requestId", "req-91");

        List<String> steps = containment.onBlock(event, "Export outside the delegation");

        assertThat(steps).containsExactly("DELEGATION_REVOKED", "TOKENS_REVOKED(2)", "DELEGATOR_NOTIFIED(MAIL)");
        assertThat(delegations.find(delegation.delegationId())).map(AgentDelegation::revokedBy)
                .contains(AgentContainmentService.REVOKED_BY);
        // The tokens the agent's client holds for the person, not the person's own.
        assertThat(revoked).containsExactly("alice/report-client");
        assertThat(noticeStore.list(null, 10)).singleElement().satisfies(notice -> {
            assertThat(notice.recipientId()).isEqualTo("alice");
            assertThat(notice.kind()).isEqualTo(AgentNotice.AGENT_STOPPED);
            assertThat(notice.delegationId()).isEqualTo(delegation.delegationId());
            assertThat(notice.correlationId()).isEqualTo("req-91");
            assertThat(notice.deliveredBy()).isEqualTo("MAIL");
        });
        // The person's own decision and the agent's registration stay.
        assertThat(actions.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(registry.find(null, "report-agent")).map(AgentRegistration::status).contains(AgentStatus.ACTIVE);
        AuditRecord record = auditRecord();
        assertThat(record.getEventCategory()).isEqualTo(AuditEventCategory.AGENT_STOPPED);
        assertThat(record.getSubjectKind()).isEqualTo("DELEGATED_AGENT");
        assertThat(record.getDelegatorId()).isEqualTo("alice");
        assertThat(record.getDelegationId()).isEqualTo(delegation.delegationId());
        assertThat(record.getCorrelationId()).isEqualTo("req-91");
        assertThat(record.getDetails()).containsEntry("steps",
                "DELEGATION_REVOKED, TOKENS_REVOKED(2), DELEGATOR_NOTIFIED(MAIL)");
    }

    @Test
    void aBlockOfAnAgentActingOnItsOwnSuspendsItAndTellsItsSponsor() {
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", null, "sync-client", "carol",
                true));

        List<String> steps = containment.onBlock(new ZeroTrustSubject(null, "sync-client",
                SubjectKind.AUTONOMOUS_AGENT, "sync-agent", null), null,
                null, "Bulk export at night", "req-7");

        assertThat(steps).containsExactly("AGENT_SUSPENDED", "TOKENS_REVOKED(2)", "SPONSOR_NOTIFIED(MAIL)");
        assertThat(registry.find(null, "sync-agent")).hasValueSatisfying(agent -> {
            assertThat(agent.status()).isEqualTo(AgentStatus.SUSPENDED);
            assertThat(agent.statusReason()).isEqualTo("BLOCK: Bulk export at night");
        });
        // Its own tokens: the client is the principal of a client-credentials token.
        assertThat(revoked).containsExactly("sync-client/sync-client");
        // Without an accountable person on the request, the sponsor the registration names is told.
        assertThat(noticeStore.list(null, 10)).singleElement()
                .satisfies(notice -> assertThat(notice.recipientId()).isEqualTo("carol"));
    }

    /**
     * CF-13: an agent admitted under the single-tenant registration is stopped when a request in a tenant is blocked,
     * as the event publisher reads that registration for the tenant's request.
     */
    @Test
    void aBlockInATenantStopsTheAgentRegisteredWithoutATenant() {
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", null, "sync-client", "carol",
                true));

        List<String> steps = containment.onBlock(new ZeroTrustSubject("tenant-a", "sync-client",
                SubjectKind.AUTONOMOUS_AGENT, "sync-agent", null), null, null, "Bulk export at night", "req-8");

        assertThat(steps).containsExactly("AGENT_SUSPENDED", "TOKENS_REVOKED(2)", "SPONSOR_NOTIFIED(MAIL)");
        assertThat(registry.find(null, "sync-agent")).map(AgentRegistration::status).contains(AgentStatus.SUSPENDED);
    }

    @Test
    void aReportedAgentIsBlockedAtOnceAndStoppedAsABlockStopsIt() {
        AgentDelegation delegation = delegations.record(new AgentDelegationRequest(null, "alice", "report-agent", null,
                "REPORTING", "Prepare the weekly HX-310 drawing report", List.of("READ"), List.of("HX-310"), null,
                null, null, NOW.minusSeconds(3600), NOW.plus(Duration.ofDays(3)), null, null));

        List<String> steps = containment.onReport(new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT,
                "report-agent", delegation.delegationId()), "alice", "I never asked for this", "req-5");

        assertThat(steps).startsWith("AGENT_BLOCKED", "DELEGATION_REVOKED");
        assertThat(actions.getCurrentAction("alice::agent::report-agent")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actions.getCurrentAction("alice")).isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(delegations.find(delegation.delegationId())).map(AgentDelegation::revokedAt).isPresent();
        assertThat(auditRecord().getReason()).isEqualTo("Reported by alice: I never asked for this");
    }

    @Test
    void aPersonsBlockIsNoAgentStop() {
        SecurityEvent event = SecurityEvent.builder().userId("alice").build();

        assertThat(containment.onBlock(event, "Impossible travel")).isEmpty();
        assertThat(containment.onBlock(ZeroTrustSubject.person("alice"), "client", null, "x", null)).isEmpty();
        assertThat(revoked).isEmpty();
        assertThat(noticeStore.list(null, 10)).isEmpty();
        verify(audit, never()).recordSync(any());
    }

    @Test
    void aFailingStepIsRecordedAndTheOthersStillRun() {
        AgentContainmentService failing = new AgentContainmentService(actions, registry, delegations,
                (principal, clientId) -> {
                    throw new IllegalStateException("authorization server down");
                }, new AgentNotices(noticeStore, null, Clock.fixed(NOW, ZoneOffset.UTC)), audit);
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", null, "sync-client", "carol",
                true));

        List<String> steps = failing.onBlock(new ZeroTrustSubject(null, "sync-client",
                SubjectKind.AUTONOMOUS_AGENT, "sync-agent", null), null,
                "dave", "Bulk export", null);

        assertThat(steps).containsExactly("AGENT_SUSPENDED", "TOKEN_REVOCATION_FAILED", "SPONSOR_NOTIFIED(CONSOLE)");
        assertThat(noticeStore.list(null, 10)).singleElement()
                .satisfies(notice -> assertThat(notice.recipientId()).isEqualTo("dave"));
    }

    @Test
    void releasingAnAgentStoppedForAPersonClearsOnlyItsDecisionsForThatPerson() {
        actions.saveAction("alice", ZeroTrustAction.ALLOW, Map.of());
        actions.saveAction("alice::agent::report-agent", ZeroTrustAction.BLOCK, Map.of());
        actions.saveAction("bob::agent::report-agent", ZeroTrustAction.BLOCK, Map.of());

        containment.releaseDelegatedAgent("alice", "report-agent", "admin", "reviewed");

        assertThat(actions.getCurrentAction("alice::agent::report-agent")).isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actions.getCurrentAction("bob::agent::report-agent")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actions.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.ALLOW);
        AuditRecord record = auditRecord();
        assertThat(record.getEventCategory()).isEqualTo(AuditEventCategory.AGENT_RELEASED);
        assertThat(record.getPrincipalName()).isEqualTo("admin");
        assertThat(record.getDelegatorId()).isEqualTo("alice");
        assertThat(record.getReason()).isEqualTo("reviewed");
    }

    @Test
    void releasingASuspendedAgentResumesItAndClearsItsOwnDecisions() {
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", null, "sync-client", "carol",
                true));
        registry.suspend(null, "sync-agent", "BLOCK: Bulk export");
        actions.saveAction("sync-client", ZeroTrustAction.BLOCK, Map.of());

        assertThat(containment.releaseAgent(null, "sync-agent", "admin", "reviewed")).isTrue();
        assertThat(containment.releaseAgent(null, "unknown-agent", "admin", "reviewed")).isFalse();

        assertThat(registry.find(null, "sync-agent")).map(AgentRegistration::status).contains(AgentStatus.ACTIVE);
        assertThat(actions.getCurrentAction("sync-client")).isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThatThrownBy(() -> containment.releaseDelegatedAgent(" ", "report-agent", "admin", "x"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theKillSwitchSuspendsTheActiveAgentsInScopeAndItsReleaseResumesOnlyThose() {
        registry.register(new AgentRegistrationRequest(null, "a1", "A1", "REPORTING", "c1", "carol", true));
        registry.register(new AgentRegistrationRequest(null, "a2", "A2", "REPORTING", "c2", "carol", true));
        registry.register(new AgentRegistrationRequest(null, "a3", "A3", "SYNC", "c3", "carol", true));
        registry.register(new AgentRegistrationRequest(null, "a4", "A4", "REPORTING", "c4", "carol", true));
        registry.suspend(null, "a2", "BLOCK: earlier decision");

        assertThat(containment.killSwitch(null, "REPORTING", "admin", "incident 42")).containsExactlyInAnyOrder("a1",
                "a4");
        assertThat(registry.find(null, "a3")).map(AgentRegistration::status).contains(AgentStatus.ACTIVE);
        assertThat(registry.find(null, "a1")).map(AgentRegistration::statusReason)
                .contains(AgentContainmentService.KILL_SWITCH_REASON + "incident 42");

        assertThat(containment.releaseKillSwitch(null, "REPORTING", "admin", "incident closed"))
                .containsExactlyInAnyOrder("a1", "a4");
        assertThat(registry.find(null, "a1")).map(AgentRegistration::status).contains(AgentStatus.ACTIVE);
        // An agent a decision stopped stays stopped.
        assertThat(registry.find(null, "a2")).map(AgentRegistration::status).contains(AgentStatus.SUSPENDED);
        ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit, atLeastOnce()).recordSync(records.capture());
        assertThat(records.getAllValues()).extracting(AuditRecord::getAction)
                .containsExactly("KILL_SWITCH_ON", "KILL_SWITCH_OFF");
    }

    private AuditRecord auditRecord() {
        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordSync(record.capture());
        return record.getValue();
    }
}
