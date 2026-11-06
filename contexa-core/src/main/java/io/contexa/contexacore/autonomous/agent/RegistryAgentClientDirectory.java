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
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * The approved agents of the agent registry (A1-2, AG-12b): a client is an agent when the registry holds it as
 * allowlisted through the life cycle interface and in service. An agent only observed in requests, registered as not
 * approved, suspended or deregistered is not one. A registry that cannot answer names no agent, so a token it cannot
 * vouch for is refused rather than admitted.
 */
@Slf4j
public class RegistryAgentClientDirectory implements AgentClientDirectory {

    private final AgentRegistry registry;
    private final RequestPathDatabaseGuard requestPathDatabaseGuard;

    public RegistryAgentClientDirectory(AgentRegistry registry) {
        this(registry, new RequestPathDatabaseGuard());
    }

    public RegistryAgentClientDirectory(AgentRegistry registry, RequestPathDatabaseGuard requestPathDatabaseGuard) {
        this.registry = registry;
        this.requestPathDatabaseGuard = requestPathDatabaseGuard;
    }

    @Override
    public Optional<String> activeAgentForClient(String tenantId, String clientId) {
        if (registry == null || AgentRegistrations.blank(clientId)) {
            return Optional.empty();
        }
        try {
            return find(tenantId, clientId)
                    .filter(registration -> registration.allowlisted() && registration.status() == AgentStatus.ACTIVE)
                    .map(AgentRegistration::agentId);
        } catch (RuntimeException e) {
            log.error("Agent registry lookup failed; the client is not taken as an agent. clientId={}", clientId, e);
            return Optional.empty();
        }
    }

    /**
     * Suspended when a registration the token answers to is: for a token that names a tenant, that tenant's and the
     * single-tenant deployment's (the stricter of the two, as a request in the tenant reads it); for a token that names
     * none, as every token Contexa issues, the client's in every tenant, since such a token is bound to none.
     */
    @Override
    public boolean suspendedAgentClient(String tenantId, String clientId) {
        if (registry == null || AgentRegistrations.blank(clientId)) {
            return false;
        }
        try {
            List<AgentRegistration> registrations = AgentRegistrations.blank(tenantId)
                    ? everyTenant(clientId)
                    : Stream.concat(find(tenantId, clientId).stream(), find(null, clientId).stream()).toList();
            return registrations.stream().anyMatch(registration -> registration.status() == AgentStatus.SUSPENDED);
        } catch (RuntimeException e) {
            log.error("Agent registry lookup failed; the client's suspension is not known. clientId={}", clientId, e);
            return false;
        }
    }

    /**
     * The tenant that registered the client's agent: none when the single-tenant deployment registered it, and none
     * when two tenants did, since the client then is no one tenant's. A sighting registers nothing.
     */
    @Override
    public Optional<String> tenantOfClient(String clientId) {
        if (registry == null || AgentRegistrations.blank(clientId)) {
            return Optional.empty();
        }
        try {
            List<AgentRegistration> registered = everyTenant(clientId).stream()
                    .filter(registration -> registration.source() == AgentRegistrationSource.LIFECYCLE)
                    .toList();
            if (registered.size() != 1) {
                return Optional.empty();
            }
            return Optional.ofNullable(registered.get(0).tenantId());
        } catch (RuntimeException e) {
            log.error("Agent registry lookup failed; the client's tenant is not known. clientId={}", clientId, e);
            return Optional.empty();
        }
    }

    /** A registry that does not answer in time reads as one that failed: the client is not taken as an agent. */
    private Optional<AgentRegistration> find(String tenantId, String clientId) {
        return requestPathDatabaseGuard.call(() -> registry.findByClientId(tenantId, clientId), Optional.empty());
    }

    private List<AgentRegistration> everyTenant(String clientId) {
        return requestPathDatabaseGuard.call(() -> registry.findAllByClientId(clientId), List.of());
    }
}
