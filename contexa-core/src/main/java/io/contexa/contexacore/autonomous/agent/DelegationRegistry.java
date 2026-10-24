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

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * The delegations Contexa keeps (docs/agent OC-1): what each person delegated to which agent, for how long. People
 * record and revoke their own delegations through the delegation API; administrators and integrations record them
 * for others. Every agent request is decided with the delegation it runs under ({@link RegistryDelegationRecordLookup}).
 *
 * <p>Delegations are kept per tenant; a {@code null} tenant is the single-tenant deployment's. Identifiers are unique
 * across tenants.
 */
public interface DelegationRegistry {

    /** Records a delegation; refused ({@link IllegalArgumentException}) when it is incomplete or too long. */
    AgentDelegation record(AgentDelegationRequest request);

    /** The delegation of the identifier. */
    Optional<AgentDelegation> find(String delegationId);

    /**
     * The delegation the person's request through the agent runs under at the moment: the latest started one that
     * holds then, else the latest one at all (its end is then a fact). Empty when the person never delegated to the
     * agent in the tenant.
     */
    Optional<AgentDelegation> current(@Nullable String tenantId, String delegatorId, String agentId, Instant at);

    /**
     * The tenant's delegations (every tenant's for {@code null}) of the delegator and of the agent when they are
     * given, latest started first, at most {@code limit}.
     */
    List<AgentDelegation> list(@Nullable String tenantId, @Nullable String delegatorId, @Nullable String agentId,
                               int limit);

    /** Revokes the delegation at once; an ended one stays as it was. Empty when it is unknown. */
    Optional<AgentDelegation> revoke(String delegationId, String revokedBy, @Nullable String reason);

    /**
     * Removes every delegation the person gave, in every tenant, when the person's account is deleted; the number
     * removed.
     */
    int deleteByDelegator(String delegatorId);
}
