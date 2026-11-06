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

import java.util.List;
import java.util.Optional;

/**
 * The agents Contexa knows (A1-6, AG-11f). Every agent request is recorded ({@link #observe}), so an agent appears
 * even before anyone registers it. The life cycle methods ({@link #register}, {@link #deregister},
 * {@link #transferSponsor}) are how an identity provider's events reach Contexa: call them from a SCIM endpoint, a
 * provisioning webhook or a scheduled synchronisation.
 *
 * <p>Agents are kept per tenant; a {@code null} tenant is the single-tenant deployment's.
 */
public interface AgentRegistry {

    Optional<AgentRegistration> find(String tenantId, String agentId);

    /**
     * The tenant's agent whose tokens are issued to the client, or else the agent whose identifier is the client's
     * (A1-2): how a client's own token is matched to an agent. The tenant is matched exactly; {@code null} is the
     * single-tenant deployment's. The answer reflects a suspension or deregistration at once, since it admits tokens.
     */
    Optional<AgentRegistration> findByClientId(String tenantId, String clientId);

    /**
     * The client's agent in every tenant that holds one, the single-tenant deployment's included: for each tenant, what
     * {@link #findByClientId} answers there. A token that names no tenant, as every token Contexa issues, is matched to
     * an agent with it, so an agent registered in a tenant is found by its client and its suspension stops its tokens.
     * The answer reflects a life cycle change at once, as {@link #findByClientId} does. A registry that does not
     * override it reads every agent it holds.
     */
    default List<AgentRegistration> findAllByClientId(String clientId) {
        if (AgentRegistrations.blank(clientId)) {
            return List.of();
        }
        return AgentRegistrations.eachTenantsForClient(list(null, Integer.MAX_VALUE), clientId.trim());
    }

    /** The tenant's agents (every tenant's for {@code null}), latest seen first, at most {@code limit}. */
    List<AgentRegistration> list(String tenantId, int limit);

    /** Records a request of the agent: the first one registers it as observed, later ones move its last seen time. */
    AgentRegistration observe(AgentSighting sighting);

    /** The identity provider registered or updated the agent; a deregistered agent becomes active again. */
    AgentRegistration register(AgentRegistrationRequest request);

    /** The identity provider removed the agent. Empty when the registry does not know it. */
    Optional<AgentRegistration> deregister(String tenantId, String agentId, String reason);

    /** The person accountable for the agent changed. Empty when the registry does not know it. */
    Optional<AgentRegistration> transferSponsor(String tenantId, String agentId, String sponsorId);

    /**
     * docs/agent A5-3: stops the agent (a BLOCK on its own requests, an operator, the kill switch): its own tokens and
     * the tokens issued to it for people are refused until it is resumed. Empty when the registry does not know it.
     */
    default Optional<AgentRegistration> suspend(String tenantId, String agentId, String reason) {
        throw new UnsupportedOperationException("Agent suspension is not supported by " + getClass().getSimpleName());
    }

    /** docs/agent A5-3: ends the agent's suspension. Empty when the registry does not know it. */
    default Optional<AgentRegistration> resume(String tenantId, String agentId, String reason) {
        throw new UnsupportedOperationException("Agent suspension is not supported by " + getClass().getSimpleName());
    }

    /**
     * docs/agent OC-3: removes the agent and its history for good (a mistaken registration, the deletion of personal
     * data); a deregistration keeps both. Empty when the registry does not know it.
     */
    default Optional<AgentRegistration> remove(String tenantId, String agentId) {
        throw new UnsupportedOperationException("Agent removal is not supported by " + getClass().getSimpleName());
    }
}
