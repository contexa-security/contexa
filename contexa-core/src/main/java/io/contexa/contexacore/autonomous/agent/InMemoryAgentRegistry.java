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

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The agent registry held in memory (A1-6): the default when no database registry is configured, and the reference
 * for the rules every {@link AgentRegistry} follows. Agents are lost on restart.
 */
public class InMemoryAgentRegistry implements AgentRegistry {

    private final Map<AgentKey, AgentRegistration> agents = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryAgentRegistry() {
        this(Clock.systemUTC());
    }

    public InMemoryAgentRegistry(Clock clock) {
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public Optional<AgentRegistration> find(String tenantId, String agentId) {
        if (AgentRegistrations.blank(agentId)) {
            return Optional.empty();
        }
        return Optional.ofNullable(agents.get(AgentKey.of(tenantId, agentId)));
    }

    @Override
    public Optional<AgentRegistration> findByClientId(String tenantId, String clientId) {
        if (AgentRegistrations.blank(clientId)) {
            return Optional.empty();
        }
        String client = clientId.trim();
        String tenantKey = AgentRegistrations.tenantKey(tenantId);
        List<AgentRegistration> inTenant = agents.entrySet().stream()
                .filter(entry -> tenantKey.equals(entry.getKey().tenantKey()))
                .map(Map.Entry::getValue)
                .toList();
        return inTenant.stream()
                .filter(registration -> client.equals(registration.clientId()))
                .min(Comparator.comparing(AgentRegistration::agentId))
                .or(() -> inTenant.stream().filter(registration -> client.equals(registration.agentId())).findFirst());
    }

    @Override
    public Optional<AgentRegistration> remove(String tenantId, String agentId) {
        if (AgentRegistrations.blank(agentId)) {
            return Optional.empty();
        }
        return Optional.ofNullable(agents.remove(AgentKey.of(tenantId, agentId)));
    }

    @Override
    public List<AgentRegistration> list(String tenantId, int limit) {
        String tenantKey = tenantId != null ? AgentRegistrations.tenantKey(tenantId) : null;
        return agents.entrySet().stream()
                .filter(entry -> tenantKey == null || tenantKey.equals(entry.getKey().tenantKey()))
                .map(Map.Entry::getValue)
                .sorted(Comparator.comparing(AgentRegistration::lastSeenAt, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(AgentRegistration::agentId))
                .limit(Math.max(0, limit))
                .toList();
    }

    @Override
    public AgentRegistration observe(AgentSighting sighting) {
        AgentRegistrations.requireAgent(sighting != null ? sighting.agentId() : null);
        Instant seenAt = sighting.seenAt() != null ? sighting.seenAt() : clock.instant();
        return agents.compute(AgentKey.of(sighting.tenantId(), sighting.agentId()),
                (key, current) -> AgentRegistrations.observed(current, sighting, seenAt));
    }

    @Override
    public AgentRegistration register(AgentRegistrationRequest request) {
        AgentRegistrations.requireAgent(request != null ? request.agentId() : null);
        Instant now = clock.instant();
        return agents.compute(AgentKey.of(request.tenantId(), request.agentId()),
                (key, current) -> AgentRegistrations.registered(current, request, now));
    }

    @Override
    public Optional<AgentRegistration> deregister(String tenantId, String agentId, String reason) {
        if (AgentRegistrations.blank(agentId)) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        return Optional.ofNullable(agents.computeIfPresent(AgentKey.of(tenantId, agentId),
                (key, current) -> AgentRegistrations.deregistered(current, reason, now)));
    }

    @Override
    public Optional<AgentRegistration> suspend(String tenantId, String agentId, String reason) {
        if (AgentRegistrations.blank(agentId)) {
            return Optional.empty();
        }
        return Optional.ofNullable(agents.computeIfPresent(AgentKey.of(tenantId, agentId),
                (key, current) -> AgentRegistrations.suspended(current, reason)));
    }

    @Override
    public Optional<AgentRegistration> resume(String tenantId, String agentId, String reason) {
        if (AgentRegistrations.blank(agentId)) {
            return Optional.empty();
        }
        return Optional.ofNullable(agents.computeIfPresent(AgentKey.of(tenantId, agentId),
                (key, current) -> AgentRegistrations.resumed(current, reason)));
    }

    @Override
    public Optional<AgentRegistration> transferSponsor(String tenantId, String agentId, String sponsorId) {
        if (AgentRegistrations.blank(agentId)) {
            return Optional.empty();
        }
        return Optional.ofNullable(agents.computeIfPresent(AgentKey.of(tenantId, agentId),
                (key, current) -> AgentRegistrations.withSponsor(current, sponsorId)));
    }

    private record AgentKey(String tenantKey, String agentId) {

        static AgentKey of(String tenantId, String agentId) {
            return new AgentKey(AgentRegistrations.tenantKey(tenantId), agentId.trim());
        }
    }
}
