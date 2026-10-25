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

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The agent's registration as a request in a tenant reads it (CF-13, CF-33): the tenant's own registration, else the
 * single-tenant one; a row of the tenant that only observed the agent does not replace the registration, and a stricter
 * status recorded on either row stays.
 */
class AgentRegistrationsFindTest {

    private static final String TENANT = "tenant-1";
    private static final String AGENT = "agent-1";

    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();

    private void registerWithoutTenant() {
        registry.register(new AgentRegistrationRequest(null, AGENT, "Report agent", "REPORT", "client-1", "carol", true));
    }

    private void sightInTenant() {
        registry.observe(new AgentSighting(TENANT, AGENT, "AUTONOMOUS_AGENT", null, Instant.parse("2026-10-25T01:00:00Z")));
    }

    @Test
    void theSingleTenantRegistrationSpeaksForTheAgentWhenTheTenantHasNoRowOfIt() {
        registerWithoutTenant();

        Optional<AgentRegistration> found = AgentRegistrations.find(registry, TENANT, AGENT);

        assertThat(found).hasValueSatisfying(registration -> {
            assertThat(registration.sponsorId()).isEqualTo("carol");
            assertThat(registration.source()).isEqualTo(AgentRegistrationSource.LIFECYCLE);
        });
    }

    @Test
    void aRowThatOnlyObservedTheAgentInTheTenantDoesNotHideTheRegistration() {
        registerWithoutTenant();
        sightInTenant();

        AgentRegistration found = AgentRegistrations.find(registry, TENANT, AGENT).orElseThrow();

        assertThat(found.sponsorId()).isEqualTo("carol");
        assertThat(found.allowlisted()).isTrue();
        assertThat(found.clientId()).isEqualTo("client-1");
        assertThat(found.status()).isEqualTo(AgentStatus.ACTIVE);
        // The sighting of the tenant stays: when it was first seen there, and as which kind.
        assertThat(found.tenantId()).isEqualTo(TENANT);
        assertThat(found.firstSeenAt()).isEqualTo(Instant.parse("2026-10-25T01:00:00Z"));
        assertThat(found.lastSubjectKind()).isEqualTo("AUTONOMOUS_AGENT");
    }

    @Test
    void aSuspensionRecordedInTheTenantStaysWhenTheRegistrationIsActive() {
        registerWithoutTenant();
        sightInTenant();
        registry.suspend(TENANT, AGENT, "stopped by a decision");

        AgentRegistration found = AgentRegistrations.find(registry, TENANT, AGENT).orElseThrow();

        assertThat(found.status()).isEqualTo(AgentStatus.SUSPENDED);
        assertThat(found.statusReason()).isEqualTo("stopped by a decision");
        assertThat(found.sponsorId()).isEqualTo("carol");
    }

    @Test
    void aDeregistrationOfTheRegistrationStaysWhenTheTenantRowIsActive() {
        registerWithoutTenant();
        sightInTenant();
        registry.deregister(null, AGENT, "removed by its identity provider");

        AgentRegistration found = AgentRegistrations.find(registry, TENANT, AGENT).orElseThrow();

        assertThat(found.status()).isEqualTo(AgentStatus.DEREGISTERED);
        assertThat(found.statusReason()).isEqualTo("removed by its identity provider");
        assertThat(found.deregisteredAt()).isNotNull();
    }

    @Test
    void theTenantsOwnRegistrationIsTheOneReadWhenTheAgentHasOneThere() {
        registerWithoutTenant();
        registry.register(new AgentRegistrationRequest(TENANT, AGENT, null, null, null, "dave", true));
        sightInTenant();

        AgentRegistration found = AgentRegistrations.find(registry, TENANT, AGENT).orElseThrow();

        assertThat(found.sponsorId()).isEqualTo("dave");
    }

    @Test
    void anObservedRowStandsAloneWhenNoRegistrationWasMadeWithoutATenant() {
        sightInTenant();

        AgentRegistration found = AgentRegistrations.find(registry, TENANT, AGENT).orElseThrow();

        assertThat(found.source()).isEqualTo(AgentRegistrationSource.OBSERVED);
        assertThat(found.sponsorId()).isNull();
    }

    @Test
    void aRequestWithoutATenantReadsTheSingleTenantRow() {
        registerWithoutTenant();
        sightInTenant();

        assertThat(AgentRegistrations.find(registry, null, AGENT)).hasValueSatisfying(
                registration -> assertThat(registration.sponsorId()).isEqualTo("carol"));
    }

    @Test
    void anUnknownAgentIsNotFound() {
        assertThat(AgentRegistrations.find(registry, TENANT, "nobody")).isEmpty();
    }
}
