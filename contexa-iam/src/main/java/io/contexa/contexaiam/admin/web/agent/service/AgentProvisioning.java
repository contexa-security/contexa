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

import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.util.List;

/**
 * Registering and retiring agents from the console and the admin API (docs/agent OC-3): an agent comes with the OAuth2
 * client its tokens are issued to and, when it signs in with its own account, that account. The default implementation
 * works with Contexa's authorization server ({@link OAuth2AgentProvisioning}); without one, registration is refused.
 */
public interface AgentProvisioning {

    /**
     * An agent to register.
     *
     * @param tenantId      the tenant, or null for the single-tenant deployment
     * @param agentId       the agent's identifier
     * @param displayName   a name for people, or null for the identifier
     * @param agentType     the kind of agent, or null
     * @param sponsorId     the person accountable for the agent (required)
     * @param clientId      the OAuth2 client, or null for {@code <agentId>-client}
     * @param scopes        the scopes the agent's tokens may carry
     * @param ownToken      whether the agent gets its own token (client credentials); default yes
     * @param actsForPeople whether the agent exchanges a person's token to act for them (token exchange); default yes
     * @param tokenLifetime the lifetime of the agent's access tokens, or null for the configured one
     * @param account       whether the agent also signs in with an account of its own; default no
     * @param accountGroups the groups of that account, by name
     */
    record Registration(@Nullable String tenantId, String agentId, @Nullable String displayName,
                        @Nullable String agentType, String sponsorId, @Nullable String clientId,
                        @Nullable List<String> scopes, @Nullable Boolean ownToken, @Nullable Boolean actsForPeople,
                        @Nullable Duration tokenLifetime, @Nullable Boolean account,
                        @Nullable List<String> accountGroups) {
    }

    /** The registration and the secrets that are shown once: the client's secret and the account's password. */
    record Credentials(AgentRegistration registration, String clientId, @Nullable String clientSecret,
                       @Nullable String accountUsername, @Nullable String accountPassword) {
    }

    /**
     * The token lifetime a number of minutes asks for, or null for none. A number too large (or too small) for a
     * duration asks for a lifetime past the longest one, which the registration refuses, rather than failing here.
     */
    @Nullable
    static Duration tokenLifetimeOfMinutes(@Nullable Long minutes) {
        if (minutes == null) {
            return null;
        }
        long bound = OAuth2AgentProvisioning.MAX_TOKEN_LIFETIME.toMinutes() + 1;
        return Duration.ofMinutes(Math.max(-bound, Math.min(minutes, bound)));
    }

    /** Whether agents can be registered here: Contexa's authorization server runs. */
    boolean available();

    /** Without Contexa's authorization server: every change is refused and the console offers none. */
    static AgentProvisioning unavailable() {
        return new AgentProvisioning() {
            @Override
            public boolean available() {
                return false;
            }

            @Override
            public Credentials register(Registration registration, String administrator) {
                throw refused();
            }

            @Override
            public Credentials rotateSecret(String tenantId, String agentId, String administrator) {
                throw refused();
            }

            @Override
            public AgentRegistration transferSponsor(String tenantId, String agentId, String sponsorId,
                                                     String administrator) {
                throw refused();
            }

            @Override
            public AgentRegistration deregister(String tenantId, String agentId, String reason, String administrator) {
                throw refused();
            }

            @Override
            public AgentRegistration remove(String tenantId, String agentId, String administrator) {
                throw refused();
            }

            private IllegalStateException refused() {
                return new IllegalStateException("Agents cannot be registered here: Contexa's OAuth2 authorization "
                        + "server is not running");
            }
        };
    }

    /** Registers the agent with its client and, when asked, its account. */
    Credentials register(Registration registration, String administrator);

    /** Gives the agent's client a new secret; tokens already issued stay valid until they expire. */
    Credentials rotateSecret(@Nullable String tenantId, String agentId, String administrator);

    /** Makes another person accountable for the agent. */
    AgentRegistration transferSponsor(@Nullable String tenantId, String agentId, String sponsorId,
                                      String administrator);

    /**
     * Deregisters the agent: its tokens are revoked, its client's secret becomes unusable and its account is disabled;
     * the agent and its history stay.
     */
    AgentRegistration deregister(@Nullable String tenantId, String agentId, String reason, String administrator);

    /** Removes the agent, its client, its tokens and its account for good. */
    AgentRegistration remove(@Nullable String tenantId, String agentId, String administrator);
}
