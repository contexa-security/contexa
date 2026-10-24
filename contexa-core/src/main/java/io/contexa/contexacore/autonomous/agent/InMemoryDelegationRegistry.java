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

import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The delegations held in memory (docs/agent OC-1): the default without the Contexa database, and the reference for
 * the rules every {@link DelegationRegistry} follows. Delegations are lost on restart.
 */
public class InMemoryDelegationRegistry implements DelegationRegistry {

    private final Map<String, AgentDelegation> delegations = new ConcurrentHashMap<>();
    private final Duration maxValidity;
    private final Clock clock;

    public InMemoryDelegationRegistry() {
        this(null, Clock.systemUTC());
    }

    public InMemoryDelegationRegistry(@Nullable Duration maxValidity, @Nullable Clock clock) {
        this.maxValidity = maxValidity;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public AgentDelegation record(AgentDelegationRequest request) {
        AgentDelegation delegation = AgentDelegations.newDelegation(UUID.randomUUID().toString(), request,
                maxValidity, clock.instant());
        delegations.put(delegation.delegationId(), delegation);
        return delegation;
    }

    @Override
    public Optional<AgentDelegation> find(String delegationId) {
        String id = AgentDelegations.text(delegationId);
        return id == null ? Optional.empty() : Optional.ofNullable(delegations.get(id));
    }

    @Override
    public Optional<AgentDelegation> current(@Nullable String tenantId, String delegatorId, String agentId,
                                             Instant at) {
        String delegator = AgentDelegations.text(delegatorId);
        String agent = AgentDelegations.text(agentId);
        if (delegator == null || agent == null) {
            return Optional.empty();
        }
        return AgentDelegations.current(delegations.values().stream()
                .filter(delegation -> AgentDelegations.inTenant(delegation, tenantId))
                .filter(delegation -> delegator.equals(delegation.delegatorId()) && agent.equals(delegation.agentId()))
                .toList(), at != null ? at : clock.instant());
    }

    @Override
    public List<AgentDelegation> list(@Nullable String tenantId, @Nullable String delegatorId,
                                      @Nullable String agentId, int limit) {
        String delegator = AgentDelegations.text(delegatorId);
        String agent = AgentDelegations.text(agentId);
        return delegations.values().stream()
                .filter(delegation -> tenantId == null || AgentDelegations.inTenant(delegation, tenantId))
                .filter(delegation -> delegator == null || delegator.equals(delegation.delegatorId()))
                .filter(delegation -> agent == null || agent.equals(delegation.agentId()))
                .sorted(Comparator.comparing(AgentDelegation::validFrom).reversed()
                        .thenComparing(AgentDelegation::delegationId))
                .limit(Math.max(0, limit))
                .toList();
    }

    @Override
    public int deleteByDelegator(String delegatorId) {
        String delegator = AgentDelegations.text(delegatorId);
        if (delegator == null) {
            return 0;
        }
        List<String> ids = delegations.values().stream()
                .filter(delegation -> delegator.equals(delegation.delegatorId()))
                .map(AgentDelegation::delegationId)
                .toList();
        ids.forEach(delegations::remove);
        return ids.size();
    }

    @Override
    public Optional<AgentDelegation> revoke(String delegationId, String revokedBy, @Nullable String reason) {
        return find(delegationId).map(found -> delegations.compute(found.delegationId(),
                (id, current) -> AgentDelegations.revoked(current, revokedBy, reason, clock.instant())));
    }
}
