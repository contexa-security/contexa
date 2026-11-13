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
package io.contexa.contexaiam.admin.web.agent.service;

import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** IAM-D57: the sponsor of an agent in service is not removed; the agents are named. */
class AgentSponsorshipTest {

    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
    private final AgentSponsorship sponsorship = new AgentSponsorship(() -> registry, null);

    @Test
    void theSponsorOfAgentsInServiceIsNotRemoved() {
        registry.register(new AgentRegistrationRequest(null, "report-agent", null, "AGENT", "report-client", "carol", true));
        registry.register(new AgentRegistrationRequest("tenant-a", "audit-agent", null, "AGENT", "audit-client", "carol",
                true));

        assertThat(sponsorship.agentsSponsoredBy("carol")).containsExactly("audit-agent", "report-agent");
        assertThatThrownBy(() -> sponsorship.refuseRemovingTheSponsor("carol"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("audit-agent, report-agent");
    }

    @Test
    void aDeregisteredAgentOrAnotherSponsorDoesNotHoldTheAccount() {
        registry.register(new AgentRegistrationRequest(null, "old-agent", null, "AGENT", "old-client", "carol", true));
        registry.deregister(null, "old-agent", "retired");
        registry.register(new AgentRegistrationRequest(null, "report-agent", null, "AGENT", "report-client", "dave", true));

        assertThatCode(() -> sponsorship.refuseRemovingTheSponsor("carol")).doesNotThrowAnyException();
        assertThat(sponsorship.agentsSponsoredBy("dave")).containsExactly("report-agent");
    }

    @Test
    void withoutAgentsNothingIsRefused() {
        AgentSponsorship none = new AgentSponsorship(() -> null, null);

        assertThatCode(() -> none.refuseRemovingTheSponsor("carol")).doesNotThrowAnyException();
        assertThat(sponsorship.agentsSponsoredBy(null)).isEmpty();
    }
}
