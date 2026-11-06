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

import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * The agent a client is and its suspension, read alike from every agent registry. A token Contexa issues names no
 * tenant: the suspension of the client in any tenant stops such a token, and the token engine reads the agent in the
 * tenant that registered the client. A token that names a tenant still reads that tenant only.
 */
public abstract class AbstractAgentClientTenantContractTest {

    private static final Instant SEEN = Instant.parse("2026-11-06T01:00:00Z");

    private AgentRegistry registry;
    private AgentClientDirectory directory;

    /** A new, empty registry of the kind under test. */
    protected abstract AgentRegistry newRegistry();

    @BeforeEach
    void openRegistry() {
        registry = newRegistry();
        directory = new RegistryAgentClientDirectory(registry);
    }

    @Test
    void theSuspensionOfAnAgentOfATenantStopsATokenNamingNoTenant() {
        register("tenant-a", "tenant-bot", "tenant-client");
        assertThat(directory.suspendedAgentClient(null, "tenant-client")).isFalse();

        registry.suspend("tenant-a", "tenant-bot", "stopped");

        assertThat(directory.suspendedAgentClient(null, "tenant-client")).isTrue();
        assertThat(directory.suspendedAgentClient("tenant-a", "tenant-client")).isTrue();
    }

    @Test
    void theTenantThatRegisteredTheClientReadsItsAgent() {
        register("tenant-a", "tenant-bot", "tenant-client");

        assertThat(directory.tenantOfClient("tenant-client")).contains("tenant-a");
        assertThat(directory.activeAgentForClient("tenant-a", "tenant-client")).contains("tenant-bot");
    }

    @Test
    void controlTheAgentOfTheSingleTenantDeploymentAsBefore() {
        register(null, "solo-bot", "solo-client");

        assertThat(directory.tenantOfClient("solo-client")).isEmpty();
        assertThat(directory.activeAgentForClient(null, "solo-client")).contains("solo-bot");
        assertThat(directory.suspendedAgentClient(null, "solo-client")).isFalse();

        registry.suspend(null, "solo-bot", "stopped");

        assertThat(directory.suspendedAgentClient(null, "solo-client")).isTrue();
        assertThat(directory.activeAgentForClient(null, "solo-client")).isEmpty();
    }

    @Test
    void controlATokenReadsTheAgentOfTheTenantItNamesOnly() {
        register("tenant-a", "tenant-bot", "tenant-client");

        assertThat(directory.activeAgentForClient(null, "tenant-client")).isEmpty();
        assertThat(directory.activeAgentForClient("tenant-b", "tenant-client")).isEmpty();
        assertThat(directory.suspendedAgentClient("tenant-b", "tenant-client")).isFalse();
    }

    @Test
    void aSuspensionOfTheSingleTenantRegistrationStopsATokenNamingATenant() {
        register(null, "solo-bot", "solo-client");
        registry.suspend(null, "solo-bot", "stopped");

        assertThat(directory.suspendedAgentClient("tenant-a", "solo-client")).isTrue();
    }

    @Test
    void aSightingWithoutATenantDoesNotMoveTheClientsTenant() {
        register("tenant-a", "tenant-bot", "tenant-client");
        registry.observe(new AgentSighting(null, "tenant-bot", "AUTONOMOUS_AGENT", "tenant-client", SEEN));

        assertThat(directory.tenantOfClient("tenant-client")).contains("tenant-a");

        registry.suspend("tenant-a", "tenant-bot", "stopped");

        assertThat(directory.suspendedAgentClient(null, "tenant-client")).isTrue();
    }

    @Test
    void aSuspendedSightingOfAnotherTenantStopsATokenNamingNoTenant() {
        register(null, "solo-bot", "solo-client");
        registry.observe(new AgentSighting("tenant-a", "solo-bot", "AUTONOMOUS_AGENT", "solo-client", SEEN));

        registry.suspend("tenant-a", "solo-bot", "stopped in the tenant");

        assertThat(directory.suspendedAgentClient(null, "solo-client")).isTrue();
    }

    @Test
    void aClientTwoTenantsRegisteredIsNoOneTenantsAndAnySuspensionStopsIt() {
        register("tenant-a", "bot-a", "shared-client");
        register("tenant-b", "bot-b", "shared-client");

        assertThat(directory.tenantOfClient("shared-client")).isEmpty();
        assertThat(directory.activeAgentForClient(null, "shared-client")).isEmpty();

        registry.suspend("tenant-b", "bot-b", "stopped");

        assertThat(directory.suspendedAgentClient(null, "shared-client")).isTrue();
    }

    @Test
    void everyTenantsAgentOfAClientIsFoundAsEachTenantFindsIt() {
        register("tenant-a", "tenant-bot", "tenant-client");
        register("tenant-a", "tenant-client", "other-client");
        register(null, "solo-bot", "tenant-client");
        register("tenant-b", "unrelated", "unrelated-client");

        assertThat(registry.findAllByClientId("tenant-client"))
                .extracting(AgentRegistration::tenantId, AgentRegistration::agentId)
                .containsExactly(tuple(null, "solo-bot"),
                        tuple("tenant-a", "tenant-bot"));
        assertThat(registry.findAllByClientId("nobody")).isEmpty();
        assertThat(registry.findAllByClientId(" ")).isEmpty();
    }

    private void register(String tenantId, String agentId, String clientId) {
        registry.register(new AgentRegistrationRequest(tenantId, agentId, agentId, "AGENT", clientId, "sponsor", true));
    }
}
