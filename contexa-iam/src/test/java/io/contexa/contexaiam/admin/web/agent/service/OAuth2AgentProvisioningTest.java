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

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationSource;
import io.contexa.contexacore.autonomous.agent.AgentSighting;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurgeResult;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * docs/agent OC-3: an agent is registered with its OAuth2 client (and its account) through Contexa, its secret is
 * rotated, its sponsor transferred, and it is deregistered or removed; every change is audited.
 */
class OAuth2AgentProvisioningTest {

    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
    private final InMemoryRegisteredClientRepository clients = new InMemoryRegisteredClientRepository(
            RegisteredClient.withId("portal").clientId("portal")
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build());
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private final JdbcOperations jdbc = mock(JdbcOperations.class);
    private final UserManagementService users = mock(UserManagementService.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final GroupRepository groups = mock(GroupRepository.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final OAuth2AgentProvisioning provisioning = new OAuth2AgentProvisioning(registry, clients, encoder, jdbc,
            users, userRepository, groups, audit, Duration.ofMinutes(30));

    /** The sponsors the tests name are enabled accounts; a sponsor is the person told and asked (IAM-D70). */
    @BeforeEach
    void sponsorsAreAccounts() {
        when(userRepository.findByUsername("carol")).thenReturn(Optional.of(Users.builder().username("carol").build()));
        when(userRepository.findByUsername("dave")).thenReturn(Optional.of(Users.builder().username("dave").build()));
        when(userRepository.findByUsername("erin"))
                .thenReturn(Optional.of(Users.builder().username("erin").enabled(false).build()));
    }

    /** IAM-D57/D70: an agent nobody is accountable for is not registered, nor handed to such a sponsor. */
    @Test
    void aSponsorThatIsNoEnabledAccountIsRefused() {
        assertThatThrownBy(() -> provisioning.register(registration("agent-1", "nobody", null), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("nobody");
        assertThatThrownBy(() -> provisioning.register(registration("agent-1", "erin", null), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("erin");
        assertThat(registry.find(null, "agent-1")).isEmpty();
        assertThat(clients.findByClientId("agent-1-client")).isNull();

        register("agent-2");
        assertThatThrownBy(() -> provisioning.transferSponsor(null, "agent-2", "nobody", "admin-1"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(registry.find(null, "agent-2").orElseThrow().sponsorId()).isEqualTo("carol");
    }

    /** IAM-D67: a value longer than its column is refused with its field, and nothing is written. */
    @Test
    void aValueLongerThanItsColumnIsRefused() {
        String longId = "a".repeat(256);
        assertThatThrownBy(() -> provisioning.register(registration(longId, "carol", "short-client"), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("at most 255");
        assertThatThrownBy(() -> provisioning.register(registration("a".repeat(94), "carol", null), "admin-1"))
                .as("the client named after the agent").isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at most 100");
        assertThatThrownBy(() -> provisioning.register(new AgentProvisioning.Registration(null, "agent-1",
                "n".repeat(201), null, "carol", null, List.of("sc.engineer"), null, null, null, null, null), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("at most 200");
        assertThatThrownBy(() -> provisioning.register(new AgentProvisioning.Registration(null, "agent-1", null, null,
                "carol", null, List.of("s".repeat(1001)), null, null, null, null, null), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("at most 1000");
        assertThat(registry.find(null, "agent-1")).isEmpty();
        assertThat(clients.findByClientId("agent-1-client")).isNull();

        register("agent-2");
        assertThatThrownBy(() -> provisioning.transferSponsor(null, "agent-2", "x".repeat(256), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("at most 255");
    }

    /** IAM-D70: a token lifetime of no time, of less, or of more than a day is refused, not stored. */
    @Test
    void aTokenLifetimeOutsideOneMinuteToADayIsRefused() {
        for (Long minutes : List.of(0L, -1L, 1441L, 2147483648L, Long.MAX_VALUE, Long.MIN_VALUE)) {
            assertThatThrownBy(() -> provisioning.register(new AgentProvisioning.Registration(null, "agent-1", null,
                    null, "carol", null, List.of("sc.engineer"), null, null,
                    AgentProvisioning.tokenLifetimeOfMinutes(minutes), null, null), "admin-1"))
                    .as(minutes + " minutes").isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("token lifetime");
        }
        assertThat(clients.findByClientId("agent-1-client")).isNull();

        provisioning.register(new AgentProvisioning.Registration(null, "agent-1", null, null, "carol", null,
                List.of("sc.engineer"), null, null, AgentProvisioning.tokenLifetimeOfMinutes(1440L), null, null), "admin-1");
        assertThat(clients.findByClientId("agent-1-client").getTokenSettings().getAccessTokenTimeToLive())
                .isEqualTo(Duration.ofDays(1));
    }

    @Test
    void anAgentIsRegisteredWithItsClientAndItsAccountAndTheSecretsAreGivenOnce() {
        Group engineers = new Group();
        engineers.setId(7L);
        when(groups.findByName("Engineers")).thenReturn(Optional.of(engineers));
        when(userRepository.findByUsername("report-agent")).thenReturn(Optional.empty());

        AgentProvisioning.Credentials credentials = provisioning.register(new AgentProvisioning.Registration(null,
                "report-agent", "Report agent", null, "carol", null, List.of("sc.engineer", " sc.engineer "), null,
                null, Duration.ofMinutes(15), true, List.of("Engineers")), "admin-1");

        RegisteredClient client = clients.findByClientId("report-agent-client");
        assertThat(client).isNotNull();
        assertThat(client.getAuthorizationGrantTypes()).containsExactlyInAnyOrder(
                AuthorizationGrantType.CLIENT_CREDENTIALS, AuthorizationGrantType.TOKEN_EXCHANGE);
        assertThat(client.getScopes()).containsExactly("sc.engineer");
        assertThat(client.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(15));
        assertThat(encoder.matches(credentials.clientSecret(), client.getClientSecret())).isTrue();
        AgentRegistration registration = registry.find(null, "report-agent").orElseThrow();
        assertThat(registration.clientId()).isEqualTo("report-agent-client");
        assertThat(registration.sponsorId()).isEqualTo("carol");
        assertThat(registration.allowlisted()).isTrue();
        assertThat(registration.source()).isEqualTo(AgentRegistrationSource.LIFECYCLE);
        ArgumentCaptor<UserDto> account = ArgumentCaptor.forClass(UserDto.class);
        verify(users).createUser(account.capture());
        assertThat(account.getValue().getUsername()).isEqualTo("report-agent");
        assertThat(account.getValue().getPassword()).isEqualTo(credentials.accountPassword());
        assertThat(account.getValue().getSelectedGroupIds()).containsExactly(7L);
        assertThat(credentials.accountUsername()).isEqualTo("report-agent");
        ArgumentCaptor<AuditRecord> recorded = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(recorded.capture());
        assertThat(recorded.getValue().getEventCategory()).isEqualTo(AuditEventCategory.AGENT_REGISTERED);
        assertThat(recorded.getValue().getDetails().toString()).doesNotContain(credentials.clientSecret());
    }

    @Test
    void anIncompleteOrDuplicateRegistrationIsRefused() {
        register("agent-1");

        assertThatThrownBy(() -> provisioning.register(registration("agent-1", "carol", null), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("already registered");
        assertThatThrownBy(() -> provisioning.register(registration("agent-2", "carol", "agent-1-client"), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("already exists");
        assertThatThrownBy(() -> provisioning.register(registration("agent-3", " ", null), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("sponsor");
        assertThatThrownBy(() -> provisioning.register(new AgentProvisioning.Registration(null, "agent-4", null, null,
                "carol", null, null, false, false, null, null, null), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aClientIsNotNamedAfterAnAccount() {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(new Users()));

        assertThatThrownBy(() -> provisioning.register(registration("agent-5", "carol", "alice"), "admin-1"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("account named alice");

        assertThat(clients.findByClientId("alice")).isNull();
        assertThat(registry.find(null, "agent-5")).isEmpty();
    }

    @Test
    void anObservedAgentIsRegisteredAsItIs() {
        registry.observe(new AgentSighting(null, "seen-agent", "AUTONOMOUS_AGENT", null, Instant.now()));

        provisioning.register(registration("seen-agent", "carol", null), "admin-1");

        assertThat(registry.find(null, "seen-agent").orElseThrow().source())
                .isEqualTo(AgentRegistrationSource.LIFECYCLE);
    }

    @Test
    void theSecretIsRotatedAndTheSponsorTransferred() {
        AgentProvisioning.Credentials first = register("agent-1");

        AgentProvisioning.Credentials rotated = provisioning.rotateSecret(null, "agent-1", "admin-1");
        provisioning.transferSponsor(null, "agent-1", "dave", "admin-1");

        RegisteredClient client = clients.findByClientId("agent-1-client");
        assertThat(encoder.matches(rotated.clientSecret(), client.getClientSecret())).isTrue();
        assertThat(encoder.matches(first.clientSecret(), client.getClientSecret())).isFalse();
        assertThat(registry.find(null, "agent-1").orElseThrow().sponsorId()).isEqualTo("dave");
        assertThatThrownBy(() -> provisioning.rotateSecret(null, "nobody", "admin-1"))
                .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void aDeregisteredAgentLosesItsTokensItsSecretAndItsAccountButKeepsItsHistory() {
        AgentProvisioning.Credentials credentials = register("agent-1");
        Users account = new Users();
        account.setId(11L);
        account.setUsername("agent-1");
        account.setEnabled(true);
        when(userRepository.findByUsername("agent-1")).thenReturn(Optional.of(account));

        assertThatThrownBy(() -> provisioning.deregister(null, "agent-1", " ", "admin-1"))
                .isInstanceOf(IllegalArgumentException.class);
        AgentRegistration deregistered = provisioning.deregister(null, "agent-1", "decommissioned", "admin-1");

        assertThat(deregistered.status()).isEqualTo(AgentStatus.DEREGISTERED);
        verify(jdbc).update(eq("delete from ctxa_oauth2_authorization where registered_client_id in "
                + "(select id from ctxa_oauth2_registered_client where client_id = ?)"), eq("agent-1-client"));
        assertThat(encoder.matches(credentials.clientSecret(),
                clients.findByClientId("agent-1-client").getClientSecret())).isFalse();
        assertThat(account.isEnabled()).isFalse();
        verify(userRepository).save(account);
        assertThat(registry.find(null, "agent-1")).isPresent();
    }

    @Test
    void aRemovedAgentLeavesNothingBehind() {
        register("agent-1");
        Users account = new Users();
        account.setId(11L);
        account.setUsername("agent-1");
        when(userRepository.findByUsername("agent-1")).thenReturn(Optional.of(account));
        when(jdbc.update(eq("delete from ctxa_oauth2_registered_client where client_id = ?"), anyString())).thenReturn(1);

        UserEngineStatePurger purger = mock(UserEngineStatePurger.class);
        when(purger.purge("agent-1-client")).thenReturn(new UserEngineStatePurgeResult("agent-1-client",
                List.of("bridge-mirror-users"), Map.of()));
        provisioning.setEngineStatePurger(purger);

        provisioning.remove(null, "agent-1", "admin-1");

        verify(jdbc).update("delete from ctxa_oauth2_registered_client where client_id = ?", "agent-1-client");
        verify(users).deleteUser(11L);
        // CF-23: the engine state the agent kept under its client ID goes with it.
        verify(purger).purge("agent-1-client");
        assertThat(registry.find(null, "agent-1")).isEmpty();
        ArgumentCaptor<AuditRecord> recorded = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit, times(2)).recordAsync(recorded.capture());
        assertThat(recorded.getAllValues()).extracting(AuditRecord::getEventCategory).containsExactly(
                AuditEventCategory.AGENT_REGISTERED, AuditEventCategory.AGENT_REMOVED);
    }

    @Test
    void withoutTheAuthorizationServerEveryChangeIsRefused() {
        AgentProvisioning unavailable = AgentProvisioning.unavailable();

        assertThat(unavailable.available()).isFalse();
        assertThatThrownBy(() -> unavailable.register(registration("agent-1", "carol", null), "admin-1"))
                .isInstanceOf(IllegalStateException.class);
        verify(users, never()).createUser(any());
    }

    private AgentProvisioning.Credentials register(String agentId) {
        return provisioning.register(registration(agentId, "carol", null), "admin-1");
    }

    private static AgentProvisioning.Registration registration(String agentId, String sponsor, String clientId) {
        return new AgentProvisioning.Registration(null, agentId, null, null, sponsor, clientId, List.of("sc.engineer"),
                null, null, null, null, null);
    }
}
