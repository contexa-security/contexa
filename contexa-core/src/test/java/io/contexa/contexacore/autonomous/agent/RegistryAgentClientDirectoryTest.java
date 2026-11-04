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

import io.contexa.contexacommon.security.bridge.runtime.RequestPathDatabaseGuard;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RegistryAgentClientDirectoryTest {

    private final InMemoryAgentRegistry registry =
            new InMemoryAgentRegistry(Clock.fixed(Instant.parse("2026-10-23T01:00:00Z"), ZoneOffset.UTC));
    private final RegistryAgentClientDirectory directory = new RegistryAgentClientDirectory(registry);

    @Test
    void anApprovedAgentInServiceIsNamedByItsRegisteredIdentifier() {
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));

        assertThat(directory.activeAgentForClient(null, "report-client")).contains("report-bot");
    }

    @Test
    void anObservedAgentIsNotApproved() {
        registry.observe(new AgentSighting(null, "seen-bot", "AUTONOMOUS_AGENT", "seen-client", Instant.parse("2026-10-23T00:00:00Z")));

        assertThat(directory.activeAgentForClient(null, "seen-client")).isEmpty();
    }

    @Test
    void anAgentRegisteredAsNotApprovedIsNotNamed() {
        registry.register(new AgentRegistrationRequest(null, "draft-bot", "Draft", null, "draft-client", "carol", false));

        assertThat(directory.activeAgentForClient(null, "draft-client")).isEmpty();
    }

    @Test
    void aDeregisteredAgentIsNoLongerNamed() {
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));
        registry.deregister(null, "report-bot", "retired");

        assertThat(directory.activeAgentForClient(null, "report-client")).isEmpty();
    }

    @Test
    void theLookupStaysInTheTokensTenant() {
        registry.register(new AgentRegistrationRequest("tenant-acme", "acme-bot", "Acme bot", null, "acme-client", "erin", null));

        assertThat(directory.activeAgentForClient("tenant-acme", "acme-client")).contains("acme-bot");
        assertThat(directory.activeAgentForClient(null, "acme-client")).isEmpty();
        assertThat(directory.activeAgentForClient("tenant-other", "acme-client")).isEmpty();
    }

    @Test
    void aRegistryFailureNamesNoAgent() {
        AgentRegistry failing = new InMemoryAgentRegistry() {
            @Override
            public Optional<AgentRegistration> findByClientId(String tenantId, String clientId) {
                throw new IllegalStateException("registry unavailable");
            }
        };

        assertThat(new RegistryAgentClientDirectory(failing).activeAgentForClient(null, "report-client")).isEmpty();
        assertThat(new RegistryAgentClientDirectory(null).activeAgentForClient(null, "report-client")).isEmpty();
        assertThat(List.of(directory.activeAgentForClient(null, null), directory.activeAgentForClient(null, " ")))
                .allMatch(Optional::isEmpty);
    }

    @Test
    void aRegistryThatDoesNotAnswerDoesNotHoldTheRequest() {
        CountDownLatch databaseBack = new CountDownLatch(1);
        AgentRegistry hanging = mock(AgentRegistry.class);
        when(hanging.findByClientId(any(), any())).thenAnswer(call -> {
            databaseBack.await();
            return Optional.empty();
        });
        RequestPathDatabaseGuard guard = new RequestPathDatabaseGuard(Duration.ofMillis(150), 4);
        RegistryAgentClientDirectory outage = new RegistryAgentClientDirectory(hanging, guard);
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(3), () -> {
                assertThat(outage.activeAgentForClient(null, "report-client")).isEmpty();
                assertThat(outage.suspendedAgentClient(null, "report-client")).isFalse();
            });
        } finally {
            databaseBack.countDown();
            guard.destroy();
        }
    }
}
