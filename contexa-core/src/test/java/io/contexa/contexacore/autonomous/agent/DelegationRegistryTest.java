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

import io.contexa.contexacore.autonomous.context.enricher.DelegationRecord;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecordQuery;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent OC-1: the delegations Contexa keeps, and the delegation record an agent request is decided with, without
 * application code.
 */
class DelegationRegistryTest {

    private static final Instant NOW = Instant.parse("2026-10-23T05:00:00Z");

    private final InMemoryDelegationRegistry registry = new InMemoryDelegationRegistry(Duration.ofDays(30),
            Clock.fixed(NOW, ZoneOffset.UTC));
    private final RegistryDelegationRecordLookup lookup = new RegistryDelegationRecordLookup(registry,
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void aDelegationIsRecordedNormalisedAndReadAsTheDecisionReadsIt() {
        AgentDelegation recorded = registry.record(request(null, "alice", " report-agent ", NOW.minusSeconds(3600),
                NOW.plus(Duration.ofDays(7)), List.of("read", " READ ", "export"), List.of(" HX-310 ", "HX-310")));

        assertThat(recorded.delegationId()).isNotBlank();
        assertThat(recorded.agentId()).isEqualTo("report-agent");
        assertThat(recorded.allowedOperations()).containsExactly("READ", "EXPORT");
        assertThat(recorded.allowedResources()).containsExactly("HX-310");
        assertThat(recorded.recordedBy()).isEqualTo("alice");
        assertThat(recorded.recordedAt()).isEqualTo(NOW);
        DelegationRecord record = recorded.toRecord();
        assertThat(record.delegatorId()).isEqualTo("alice");
        assertThat(record.expiresAt()).isEqualTo(NOW.plus(Duration.ofDays(7)));
        assertThat(record.objectiveSummary()).isEqualTo("Prepare the weekly HX-310 drawing report");
        assertThat(registry.find(recorded.delegationId())).contains(recorded);
    }

    @Test
    void anIncompleteOrTooLongDelegationIsRefused() {
        assertThatThrownBy(() -> registry.record(request(null, " ", "agent", null, NOW.plusSeconds(60), null, null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> registry.record(request(null, "alice", "agent", null, null, null, null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> registry.record(request(null, "alice", "agent", NOW, NOW, null, null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> registry.record(request(null, "alice", "agent", NOW, NOW.plus(Duration.ofDays(31)),
                null, null))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aRequestRunsUnderThePersonsHoldingDelegationElseTheLatestWithItsEnd() {
        registry.record(request(null, "alice", "agent-7", NOW.minus(Duration.ofDays(10)),
                NOW.minus(Duration.ofDays(3)), null, null));
        AgentDelegation holding = registry.record(request(null, "alice", "agent-7", NOW.minus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(1)), null, null));
        AgentDelegation later = registry.record(request(null, "alice", "agent-7", NOW.plus(Duration.ofDays(2)),
                NOW.plus(Duration.ofDays(3)), null, null));
        registry.record(request(null, "bob", "agent-7", NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(1)),
                null, null));

        assertThat(lookup.find(query(null, "alice", "agent-7", null, NOW)).map(DelegationRecord::delegationId))
                .contains(holding.delegationId());
        // After every delegation ended, the latest started one is the fact.
        assertThat(lookup.find(query(null, "alice", "agent-7", null, NOW.plus(Duration.ofDays(5))))
                .map(DelegationRecord::delegationId)).contains(later.delegationId());
        assertThat(lookup.find(query(null, "carol", "agent-7", null, NOW))).isEmpty();
    }

    @Test
    void theNamedDelegationComesFirstAndARequestOfATenantFallsBackToTheSingleTenantDeployments() {
        AgentDelegation named = registry.record(request(null, "alice", "agent-7", NOW.minus(Duration.ofDays(5)),
                NOW.minus(Duration.ofDays(4)), null, null));
        AgentDelegation single = registry.record(request(null, "alice", "agent-7", NOW.minusSeconds(60),
                NOW.plusSeconds(3600), null, null));
        AgentDelegation tenant = registry.record(request("t-1", "alice", "agent-9", NOW.minusSeconds(60),
                NOW.plusSeconds(3600), null, null));

        assertThat(lookup.find(query("t-1", "alice", "agent-7", named.delegationId(), NOW))
                .map(DelegationRecord::delegationId)).contains(named.delegationId());
        assertThat(lookup.find(query("t-1", "alice", "agent-7", null, NOW)).map(DelegationRecord::delegationId))
                .contains(single.delegationId());
        assertThat(lookup.find(query("t-1", "alice", "agent-9", null, NOW)).map(DelegationRecord::delegationId))
                .contains(tenant.delegationId());
        assertThat(lookup.find(query("t-2", "alice", "agent-9", null, NOW))).isEmpty();
    }

    @Test
    void aRevokedDelegationEndsAtItsRevocationAndStaysAsAFact() {
        AgentDelegation delegation = registry.record(request(null, "alice", "agent-7", NOW.minusSeconds(3600),
                NOW.plus(Duration.ofDays(1)), null, null));

        AgentDelegation revoked = registry.revoke(delegation.delegationId(), "alice", "agent hijacked").orElseThrow();

        assertThat(revoked.revokedAt()).isEqualTo(NOW);
        assertThat(revoked.revokedBy()).isEqualTo("alice");
        assertThat(revoked.revokeReason()).isEqualTo("agent hijacked");
        assertThat(revoked.validAt(NOW)).isFalse();
        assertThat(lookup.find(query(null, "alice", "agent-7", null, NOW)).map(DelegationRecord::expiresAt))
                .contains(NOW);
        // A second revocation keeps the first.
        assertThat(registry.revoke(delegation.delegationId(), "admin", "again").orElseThrow().revokedBy())
                .isEqualTo("alice");
        assertThat(registry.revoke("unknown", "admin", null)).isEmpty();
        assertThat(registry.list(null, "alice", null, 10)).containsExactly(revoked);
    }

    @Test
    void anIntegrationStatesWhoWroteTheRecordAndWhen() {
        AgentDelegation imported = registry.record(new AgentDelegationRequest(null, "alice", "agent-7", "OBJ-1",
                "REPORTING", null, List.of("READ"), List.of("HX-310"), true, false, null,
                NOW.minusSeconds(3600), NOW.plusSeconds(3600), "hr-system", NOW.minusSeconds(7200)));

        assertThat(imported.recordedBy()).isEqualTo("hr-system");
        assertThat(imported.recordedAt()).isEqualTo(NOW.minusSeconds(7200));
        assertThat(imported.toRecord().approvalRequired()).isTrue();
        assertThat(imported.toRecord().privilegedExportAllowed()).isFalse();
    }

    @Test
    void aDeletedAccountsDelegationsGoWithItInEveryTenantAndOnlyThose() {
        registry.record(request(null, "alice", "agent-7", NOW, NOW.plusSeconds(3600), null, null));
        registry.record(request("t-1", "alice", "agent-9", NOW, NOW.plusSeconds(3600), null, null));
        AgentDelegation bobs = registry.record(request(null, "bob", "agent-7", NOW, NOW.plusSeconds(3600), null, null));
        DelegationPurgeContributor contributor = new DelegationPurgeContributor(registry);

        contributor.purge("alice");

        assertThat(contributor.name()).isEqualTo("delegations");
        assertThat(registry.list(null, null, null, 10)).containsExactly(bobs);
        assertThat(registry.deleteByDelegator(" ")).isZero();
    }

    private static AgentDelegationRequest request(String tenant, String delegator, String agent, Instant from,
                                                  Instant until, List<String> operations, List<String> resources) {
        return new AgentDelegationRequest(tenant, delegator, agent, null, "REPORTING",
                "Prepare the weekly HX-310 drawing report", operations, resources, null, null, null, from, until,
                null, null);
    }

    private static DelegationRecordQuery query(String tenant, String delegator, String agent, String delegationId,
                                               Instant at) {
        return new DelegationRecordQuery(tenant, delegator, agent, delegationId, null, at);
    }
}
