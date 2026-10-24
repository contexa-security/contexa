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

import io.contexa.contexacore.autonomous.context.enricher.DelegationRecord;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecordLookup;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecordQuery;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * The delegation record of an agent request read from the delegations Contexa keeps (docs/agent OC-1): the default
 * {@link DelegationRecordLookup}, so every agent request is decided with its delegation without application code. The
 * delegation the request names (a token's {@code delegation_id}) comes first; else the person's current delegation to
 * the agent in the request's tenant, then in the single-tenant deployment. An application that keeps delegations in
 * its own system declares its own lookup instead.
 */
public class RegistryDelegationRecordLookup implements DelegationRecordLookup {

    private final DelegationRegistry registry;
    private final Clock clock;

    public RegistryDelegationRecordLookup(DelegationRegistry registry) {
        this(registry, Clock.systemUTC());
    }

    public RegistryDelegationRecordLookup(DelegationRegistry registry, Clock clock) {
        if (registry == null) {
            throw new IllegalArgumentException("A delegation registry is required");
        }
        this.registry = registry;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public Optional<DelegationRecord> find(DelegationRecordQuery query) {
        if (query == null) {
            return Optional.empty();
        }
        String delegationId = AgentDelegations.text(query.delegationId());
        if (delegationId != null) {
            Optional<AgentDelegation> named = registry.find(delegationId);
            if (named.isPresent()) {
                return named.map(AgentDelegation::toRecord);
            }
        }
        String delegator = AgentDelegations.text(query.delegatorId());
        String agent = AgentDelegations.text(query.agentId());
        if (delegator == null || agent == null) {
            return Optional.empty();
        }
        Instant at = query.requestedAt() != null ? query.requestedAt() : clock.instant();
        String tenant = AgentDelegations.text(query.tenantId());
        Optional<AgentDelegation> found = registry.current(tenant, delegator, agent, at);
        if (found.isEmpty() && tenant != null) {
            found = registry.current(null, delegator, agent, at);
        }
        return found.map(AgentDelegation::toRecord);
    }
}
