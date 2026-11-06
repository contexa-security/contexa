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
import io.contexa.contexacommon.security.subject.AgentClientStatusUnavailableException;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * The approved agents of the agent registry (A1-2, AG-12b): a client is an agent when the registry holds it as
 * allowlisted through the life cycle interface and in service. An agent only observed in requests, registered as not
 * approved, suspended or deregistered is not one. A registry that cannot answer names no agent, so a token it cannot
 * vouch for is refused rather than admitted; and it cannot say a client is not suspended either: the suspension of a
 * client it could not read is reported as unreadable, never as absent, since a failure must not lift a restriction.
 */
@Slf4j
public class RegistryAgentClientDirectory implements AgentClientDirectory {

    private static final long REPORT_INTERVAL_NANOS = TimeUnit.MINUTES.toNanos(1);
    private static final int REPORTED_CLIENTS_LIMIT = 1024;

    private final AgentRegistry registry;
    private final RequestPathDatabaseGuard requestPathDatabaseGuard;
    private final LongSupplier nanoClock;
    private final Map<String, Long> reportedAt = new ConcurrentHashMap<>();

    public RegistryAgentClientDirectory(AgentRegistry registry) {
        this(registry, new RequestPathDatabaseGuard());
    }

    public RegistryAgentClientDirectory(AgentRegistry registry, RequestPathDatabaseGuard requestPathDatabaseGuard) {
        this(registry, requestPathDatabaseGuard, System::nanoTime);
    }

    RegistryAgentClientDirectory(AgentRegistry registry, RequestPathDatabaseGuard requestPathDatabaseGuard,
                                 LongSupplier nanoClock) {
        this.registry = registry;
        this.requestPathDatabaseGuard = requestPathDatabaseGuard;
        this.nanoClock = nanoClock;
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
     *
     * @throws AgentClientStatusUnavailableException when the registry fails or does not answer in time: a suspension is a
     *                                               restriction, and the failure of the store that holds it must not lift it
     */
    @Override
    public boolean suspendedAgentClient(String tenantId, String clientId) {
        if (registry == null || AgentRegistrations.blank(clientId)) {
            return false;
        }
        try {
            List<AgentRegistration> registrations = new ArrayList<>();
            if (AgentRegistrations.blank(tenantId)) {
                registrations.addAll(answered(requestPathDatabaseGuard.call(
                        () -> registry.findAllByClientId(clientId), null)));
            } else {
                answered(requestPathDatabaseGuard.call(() -> registry.findByClientId(tenantId, clientId), null))
                        .ifPresent(registrations::add);
                answered(requestPathDatabaseGuard.call(() -> registry.findByClientId(null, clientId), null))
                        .ifPresent(registrations::add);
            }
            return registrations.stream().anyMatch(registration -> registration.status() == AgentStatus.SUSPENDED);
        } catch (AgentClientStatusUnavailableException unreadable) {
            reportUnreadable(clientId, unreadable);
            throw unreadable;
        } catch (RuntimeException failed) {
            reportUnreadable(clientId, failed);
            throw new AgentClientStatusUnavailableException(
                    "The suspension of the client " + clientId + " cannot be read", failed);
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

    /** The guard answers null when the registry did not answer in time (or its store is known to be down). */
    private static <T> T answered(T answer) {
        if (answer == null) {
            throw new AgentClientStatusUnavailableException("The agent registry did not answer in time");
        }
        return answer;
    }

    /**
     * One error line for a client in a while, not one for every request that meets the outage: the line names the client,
     * never a value of the request. The table of reported clients is bounded.
     */
    private void reportUnreadable(String clientId, RuntimeException cause) {
        long now = nanoClock.getAsLong();
        if (reportedAt.size() >= REPORTED_CLIENTS_LIMIT) {
            reportedAt.clear();
        }
        boolean[] due = {false};
        reportedAt.compute(clientId, (client, last) -> {
            if (last == null || now - last >= REPORT_INTERVAL_NANOS) {
                due[0] = true;
                return now;
            }
            return last;
        });
        if (due[0]) {
            log.error("Agent registry lookup failed; the tokens of the client are refused until the registry answers. clientId={}",
                    clientId, cause);
        }
    }
}
