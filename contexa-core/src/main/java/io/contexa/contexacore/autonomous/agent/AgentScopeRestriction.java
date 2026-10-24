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

import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;

/**
 * The narrowed scope of an agent's requests (docs/agent A5-4, IETF Transaction Tokens: a scope only narrows): until
 * {@code until}, only the operations of {@code allowed} pass. A later narrowing intersects with it and never widens
 * it; it ends only when its period ends.
 *
 * @param subjectKey  the key the agent's decisions are kept under (the agent's own for a delegated agent)
 * @param tenantId    the tenant, or null
 * @param userId      the user the requests run as
 * @param agentId     the agent
 * @param allowed     the operations that still pass
 * @param reason      why it was narrowed, the latest decision's
 * @param correlationId the request whose decision narrowed it last, or null
 * @param narrowedAt  when it was first narrowed
 * @param until       when the narrowing ends
 */
public record AgentScopeRestriction(String subjectKey, @Nullable String tenantId, String userId, String agentId,
                                    Set<ActionFamily> allowed, String reason, @Nullable String correlationId,
                                    Instant narrowedAt, Instant until) {

    public AgentScopeRestriction {
        allowed = allowed == null || allowed.isEmpty() ? EnumSet.noneOf(ActionFamily.class) : EnumSet.copyOf(allowed);
    }

    /** Whether it is in force at the moment. */
    public boolean activeAt(Instant at) {
        return at != null && at.isBefore(until);
    }

    /** Whether a request of the operation passes it. */
    public boolean allows(ActionFamily operation) {
        return operation != null && allowed.contains(operation);
    }

    /**
     * This narrowing and a later one together: the operations both allow, until the later of the two ends, with the
     * later one's reason. Nothing that this one refuses is allowed again.
     */
    public AgentScopeRestriction narrowedBy(AgentScopeRestriction later) {
        EnumSet<ActionFamily> both = allowed.isEmpty() ? EnumSet.noneOf(ActionFamily.class) : EnumSet.copyOf(allowed);
        both.retainAll(later.allowed());
        return new AgentScopeRestriction(subjectKey, tenantId, userId, agentId, both, later.reason(),
                later.correlationId(), narrowedAt, later.until().isAfter(until) ? later.until() : until);
    }
}
