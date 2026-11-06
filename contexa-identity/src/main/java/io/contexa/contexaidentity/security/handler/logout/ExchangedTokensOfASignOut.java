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
package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.AgentDelegations;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Ends, when a person signs out, the tokens agents got by exchanging the person's tokens. Such a token speaks for the
 * person only while the person is signed in, unless the person delegated to that agent: the delegation then governs the
 * agent's work, and the token stays until it runs out (it ends no later than the token it was exchanged from) while the
 * delegation is read at every request. A token of a client that is no agent, or of an agent without a delegation the
 * person gave and that holds now, ends with the sign-out.
 */
@Slf4j
public class ExchangedTokensOfASignOut {

    /** The most of a person's delegations to one agent read for one exchanged token. */
    private static final int DELEGATION_CANDIDATES = 50;

    private final DeviceAwareOAuth2AuthorizationService authorizations;
    private final RegisteredClientRepository clients;
    private final Supplier<AgentClientDirectory> agents;
    private final Supplier<DelegationRegistry> delegations;

    /**
     * @param agents      the agents the application approved, or null from it where there are none
     * @param delegations the delegations people gave agents, or null from it where none are kept
     */
    public ExchangedTokensOfASignOut(DeviceAwareOAuth2AuthorizationService authorizations,
                                     RegisteredClientRepository clients,
                                     Supplier<AgentClientDirectory> agents,
                                     Supplier<DelegationRegistry> delegations) {
        Assert.notNull(authorizations, "authorizations cannot be null");
        Assert.notNull(clients, "clients cannot be null");
        Assert.notNull(agents, "agents cannot be null");
        Assert.notNull(delegations, "delegations cannot be null");
        this.authorizations = authorizations;
        this.clients = clients;
        this.agents = agents;
        this.delegations = delegations;
    }

    /** Ends the person's exchanged tokens that still work and that no delegation of the person governs. */
    public void end(String person) {
        if (person == null || person.isBlank()) {
            return;
        }
        Instant now = Instant.now();
        for (OAuth2Authorization authorization : authorizations.findUsableByPrincipalName(person)) {
            if (AuthorizationGrantType.TOKEN_EXCHANGE.equals(authorization.getAuthorizationGrantType())
                    && !delegated(person, authorization, now)) {
                authorizations.invalidateAuthorization(authorization);
            }
        }
    }

    /**
     * Whether a delegation the person gave the agent the token was issued to holds now. One that cannot be read is
     * none: the token then ends with the sign-out, as one of no delegation does.
     */
    private boolean delegated(String person, OAuth2Authorization exchanged, Instant now) {
        try {
            return delegationHolds(person, exchanged, now);
        } catch (RuntimeException e) {
            log.error("[Logout] The delegation of an exchanged token could not be read; the token ends with the sign-out. "
                    + "person={}, authorization={}", person, exchanged.getId(), e);
            return false;
        }
    }

    private boolean delegationHolds(String person, OAuth2Authorization exchanged, Instant now) {
        DelegationRegistry registry = delegations.get();
        AgentClientDirectory directory = agents.get();
        RegisteredClient client = clients.findById(exchanged.getRegisteredClientId());
        if (registry == null || directory == null || client == null) {
            return false;
        }
        String clientId = client.getClientId();
        String tenant = directory.tenantOfClient(clientId).orElse(null);
        Optional<String> agent = directory.activeAgentForClient(tenant, clientId);
        return agent.isPresent()
                && AgentDelegations.current(registry.list(tenant, person, agent.get(), DELEGATION_CANDIDATES), now)
                .filter(delegation -> delegation.validAt(now))
                .isPresent();
    }
}
