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

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/** A1-6 (AG-11f): the registry the core keeps when no database registry is configured. */
class InMemoryAgentRegistryTest {

    private static final Instant NOW = Instant.parse("2026-10-22T05:00:00Z");

    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry(Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void theFirstRequestOfAnUnknownAgentRegistersItAsObserved() {
        AgentRegistration observed = registry.observe(new AgentSighting(
                "tenant-acme", "agent-7", "DELEGATED_AGENT", "agent-client", Instant.parse("2026-10-22T04:00:00Z")));

        assertThat(observed.source()).isEqualTo(AgentRegistrationSource.OBSERVED);
        assertThat(observed.status()).isEqualTo(AgentStatus.ACTIVE);
        assertThat(observed.allowlisted()).isFalse();
        assertThat(observed.sponsorId()).isNull();
        assertThat(observed.clientId()).isEqualTo("agent-client");
        assertThat(observed.lastSubjectKind()).isEqualTo("DELEGATED_AGENT");
        assertThat(observed.firstSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:00:00Z"));
        assertThat(observed.lastSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:00:00Z"));
        assertThat(registry.find("tenant-acme", "agent-7")).contains(observed);
    }

    @Test
    void laterRequestsMoveOnlyTheLastSeenTime() {
        registry.observe(new AgentSighting("tenant-acme", "agent-7", "DELEGATED_AGENT", null,
                Instant.parse("2026-10-22T04:00:00Z")));
        registry.observe(new AgentSighting("tenant-acme", "agent-7", "AUTONOMOUS_AGENT", "agent-client",
                Instant.parse("2026-10-22T04:30:00Z")));
        AgentRegistration latest = registry.observe(new AgentSighting("tenant-acme", "agent-7", "AUTONOMOUS_AGENT",
                null, Instant.parse("2026-10-22T04:10:00Z")));

        assertThat(latest.firstSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:00:00Z"));
        // A late sighting does not move the clock back.
        assertThat(latest.lastSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:30:00Z"));
        assertThat(latest.lastSubjectKind()).isEqualTo("AUTONOMOUS_AGENT");
        assertThat(latest.clientId()).isEqualTo("agent-client");
    }

    @Test
    void aRegistrationApprovesTheAgentAndNamesItsSponsor() {
        registry.observe(new AgentSighting("tenant-acme", "agent-7", "DELEGATED_AGENT", null,
                Instant.parse("2026-10-22T04:00:00Z")));

        AgentRegistration registered = registry.register(new AgentRegistrationRequest(
                "tenant-acme", "agent-7", "Report assistant", "report-blueprint", "agent-client", "carol", null));

        assertThat(registered.source()).isEqualTo(AgentRegistrationSource.LIFECYCLE);
        assertThat(registered.allowlisted()).isTrue();
        assertThat(registered.sponsorId()).isEqualTo("carol");
        assertThat(registered.displayName()).isEqualTo("Report assistant");
        assertThat(registered.agentType()).isEqualTo("report-blueprint");
        assertThat(registered.registeredAt()).isEqualTo(NOW);
        // What was observed stays.
        assertThat(registered.firstSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:00:00Z"));
    }

    @Test
    void aRegistrationCanStateTheAgentIsNotApproved() {
        AgentRegistration registered = registry.register(new AgentRegistrationRequest(
                null, "agent-9", null, null, null, "carol", false));

        assertThat(registered.allowlisted()).isFalse();
        assertThat(registered.firstSeenAt()).isNull();
    }

    @Test
    void deregisteringKeepsTheAgentWithItsReasonAndARegistrationRestoresIt() {
        registry.register(new AgentRegistrationRequest(null, "agent-7", "Report assistant", null, null, "carol", null));

        AgentRegistration deregistered = registry.deregister(null, "agent-7", "offboarded").orElseThrow();
        AgentRegistration seenAfter = registry.observe(new AgentSighting(null, "agent-7", "AUTONOMOUS_AGENT", null,
                Instant.parse("2026-10-22T06:00:00Z")));
        AgentRegistration restored = registry.register(new AgentRegistrationRequest(
                null, "agent-7", null, null, null, null, null));

        assertThat(deregistered.status()).isEqualTo(AgentStatus.DEREGISTERED);
        assertThat(deregistered.deregisteredAt()).isEqualTo(NOW);
        assertThat(deregistered.statusReason()).isEqualTo("offboarded");
        // A deregistered agent that still calls stays deregistered; the request is a fact, not a re-registration.
        assertThat(seenAfter.status()).isEqualTo(AgentStatus.DEREGISTERED);
        assertThat(restored.status()).isEqualTo(AgentStatus.ACTIVE);
        assertThat(restored.deregisteredAt()).isNull();
        assertThat(restored.sponsorId()).isEqualTo("carol");
        assertThat(restored.displayName()).isEqualTo("Report assistant");
    }

    @Test
    void theSponsorCanBeTransferred() {
        registry.register(new AgentRegistrationRequest(null, "agent-7", null, null, null, "carol", null));

        assertThat(registry.transferSponsor(null, "agent-7", "dave").orElseThrow().sponsorId()).isEqualTo("dave");
        assertThat(registry.transferSponsor(null, "unknown-agent", "dave")).isEmpty();
        assertThat(registry.deregister(null, "unknown-agent", "gone")).isEmpty();
    }

    @Test
    void tenantsKeepTheirOwnAgentsAndTheListShowsTheLatestSeenFirst() {
        registry.observe(new AgentSighting("tenant-a", "agent-1", "DELEGATED_AGENT", null, Instant.parse("2026-10-22T01:00:00Z")));
        registry.observe(new AgentSighting("tenant-a", "agent-2", "DELEGATED_AGENT", null, Instant.parse("2026-10-22T03:00:00Z")));
        registry.observe(new AgentSighting("tenant-b", "agent-1", "AUTONOMOUS_AGENT", null, Instant.parse("2026-10-22T02:00:00Z")));

        assertThat(registry.find("tenant-b", "agent-1").orElseThrow().lastSubjectKind()).isEqualTo("AUTONOMOUS_AGENT");
        assertThat(registry.list("tenant-a", 10)).extracting(AgentRegistration::agentId).containsExactly("agent-2", "agent-1");
        assertThat(registry.list(null, 2)).extracting(AgentRegistration::agentId).containsExactly("agent-2", "agent-1");
        assertThat(registry.list(null, 2)).extracting(AgentRegistration::tenantId).containsExactly("tenant-a", "tenant-b");
    }
}
