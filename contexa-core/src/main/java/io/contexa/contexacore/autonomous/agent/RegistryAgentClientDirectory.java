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
 * approved, suspended or deregistered is not one. A registry that cannot answer cannot say that a client is no agent, which
 * tenant it belongs to, or that it is not suspended: what it could not read is reported as unreadable, never as absent,
 * since a failure must not lift a restriction (a suspension, a delegation a person revoked) by making the client look like
 * no agent. Whoever asks stops what the client would do for now.
 * <p>
 * Reading a request (the delegation stamp of an authenticated request) does not wait for the registry: with an
 * {@link ActiveAgentList}, {@link #requestPathActiveAgentForClient} answers from the list in memory. What decides
 * something (accepting or issuing a token, a suspension, a delegation, a sign-in) is asked of the registry as before.
 */
@Slf4j
public class RegistryAgentClientDirectory implements AgentClientDirectory {

    private static final long REPORT_INTERVAL_NANOS = TimeUnit.MINUTES.toNanos(1);
    private static final int REPORTED_CLIENTS_LIMIT = 1024;

    private final AgentRegistry registry;
    private final RequestPathDatabaseGuard requestPathDatabaseGuard;
    private final ActiveAgentList activeAgents;
    private final LongSupplier nanoClock;
    private final Map<String, Long> reportedAt = new ConcurrentHashMap<>();

    public RegistryAgentClientDirectory(AgentRegistry registry) {
        this(registry, new RequestPathDatabaseGuard());
    }

    public RegistryAgentClientDirectory(AgentRegistry registry, RequestPathDatabaseGuard requestPathDatabaseGuard) {
        this(registry, requestPathDatabaseGuard, null, System::nanoTime);
    }

    /** Reads a request from the list of the approved agents in memory, when there is one. */
    public RegistryAgentClientDirectory(AgentRegistry registry, RequestPathDatabaseGuard requestPathDatabaseGuard,
                                        ActiveAgentList activeAgents) {
        this(registry, requestPathDatabaseGuard, activeAgents, System::nanoTime);
    }

    RegistryAgentClientDirectory(AgentRegistry registry, RequestPathDatabaseGuard requestPathDatabaseGuard,
                                 LongSupplier nanoClock) {
        this(registry, requestPathDatabaseGuard, null, nanoClock);
    }

    private RegistryAgentClientDirectory(AgentRegistry registry, RequestPathDatabaseGuard requestPathDatabaseGuard,
                                         ActiveAgentList activeAgents, LongSupplier nanoClock) {
        this.registry = registry;
        this.requestPathDatabaseGuard = requestPathDatabaseGuard;
        this.activeAgents = activeAgents;
        this.nanoClock = nanoClock;
    }

    /**
     * @throws AgentClientStatusUnavailableException when the registry fails or does not answer in time: a client the
     *                                               registry cannot be asked about is not "no agent"
     */
    @Override
    public Optional<String> activeAgentForClient(String tenantId, String clientId) {
        if (registry == null || AgentRegistrations.blank(clientId)) {
            return Optional.empty();
        }
        try {
            return answered(requestPathDatabaseGuard.call(() -> registry.findByClientId(tenantId, clientId), null))
                    .filter(registration -> registration.allowlisted() && registration.status() == AgentStatus.ACTIVE)
                    .map(AgentRegistration::agentId);
        } catch (RuntimeException failed) {
            throw unreadable(clientId, "The agent of the client " + clientId + " cannot be read", failed);
        }
    }

    /**
     * What {@link #activeAgentForClient} answers, from the list of the approved agents in memory: the request does not wait
     * for the registry. Without a list, it is {@link #activeAgentForClient}.
     *
     * @throws AgentClientStatusUnavailableException when the list has not been read or the registry has not answered for
     *                                               too long: a client the list cannot be asked about is not "no agent"
     */
    @Override
    public Optional<String> requestPathActiveAgentForClient(String tenantId, String clientId) {
        if (activeAgents == null) {
            return activeAgentForClient(tenantId, clientId);
        }
        if (registry == null || AgentRegistrations.blank(clientId)) {
            return Optional.empty();
        }
        return activeAgents.activeAgent(tenantId, clientId);
    }

    @Override
    public Optional<String> requestPathActiveAgentForAccount(String tenantId, String accountName) {
        return requestPathActiveAgentForClient(tenantId, accountName);
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
        } catch (RuntimeException failed) {
            throw unreadable(clientId, "The suspension of the client " + clientId + " cannot be read", failed);
        }
    }

    /**
     * The tenant that registered the client's agent: none when the single-tenant deployment registered it, and none
     * when two tenants did, since the client then is no one tenant's. A sighting registers nothing.
     *
     * @throws AgentClientStatusUnavailableException when the registry fails or does not answer in time: the agent would
     *                                               otherwise be looked up in the single-tenant deployment, where a client
     *                                               of a tenant is no agent
     */
    @Override
    public Optional<String> tenantOfClient(String clientId) {
        if (registry == null || AgentRegistrations.blank(clientId)) {
            return Optional.empty();
        }
        try {
            List<AgentRegistration> registered = answered(requestPathDatabaseGuard.call(
                    () -> registry.findAllByClientId(clientId), null)).stream()
                    .filter(registration -> registration.source() == AgentRegistrationSource.LIFECYCLE)
                    .toList();
            if (registered.size() != 1) {
                return Optional.empty();
            }
            return Optional.ofNullable(registered.get(0).tenantId());
        } catch (RuntimeException failed) {
            throw unreadable(clientId, "The tenant of the client " + clientId + " cannot be read", failed);
        }
    }

    /** What the failure of a read becomes: the unreadable answer, reported once in a while, without the cause in its text. */
    private AgentClientStatusUnavailableException unreadable(String clientId, String message, RuntimeException failed) {
        reportUnreadable(clientId, failed);
        return failed instanceof AgentClientStatusUnavailableException unavailable
                ? unavailable
                : new AgentClientStatusUnavailableException(message, failed);
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
