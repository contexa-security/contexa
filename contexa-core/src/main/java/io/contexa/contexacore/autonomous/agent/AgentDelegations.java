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

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * The rules every {@link DelegationRegistry} follows (docs/agent OC-1): what a delegation must state, how it is
 * normalised, and which delegation a request runs under.
 */
public final class AgentDelegations {

    /** The most characters of the work's description the delegator wrote. */
    public static final int SUMMARY_LIMIT = 1000;
    /** The most operations or resources one delegation names. */
    public static final int LIST_LIMIT = 100;

    private AgentDelegations() {
    }

    /**
     * The delegation the request records, checked and normalised: the delegator, the agent and the end are required,
     * the end comes after the start and the period is at most {@code maxValidity} (none when null). Operations are
     * upper-cased; operations and resources are trimmed and kept once.
     */
    public static AgentDelegation newDelegation(String delegationId, AgentDelegationRequest request,
                                                @Nullable Duration maxValidity, Instant now) {
        if (request == null) {
            throw new IllegalArgumentException("A delegation is required");
        }
        String delegator = required(request.delegatorId(), "A delegator is required");
        String agent = required(request.agentId(), "An agent is required");
        if (request.expiresAt() == null) {
            throw new IllegalArgumentException("A delegation needs an end");
        }
        Instant validFrom = request.validFrom() != null ? request.validFrom() : now;
        if (!request.expiresAt().isAfter(validFrom)) {
            throw new IllegalArgumentException("A delegation must end after it starts");
        }
        if (maxValidity != null && !maxValidity.isZero() && !maxValidity.isNegative()
                && Duration.between(validFrom, request.expiresAt()).compareTo(maxValidity) > 0) {
            throw new IllegalArgumentException("A delegation may last at most " + maxValidity);
        }
        String summary = text(request.objectiveSummary());
        if (summary != null && summary.length() > SUMMARY_LIMIT) {
            summary = summary.substring(0, SUMMARY_LIMIT);
        }
        return new AgentDelegation(delegationId, text(request.tenantId()), delegator, agent,
                text(request.objectiveId()), text(request.objectiveFamily()), summary,
                normalized(request.allowedOperations(), true), normalized(request.allowedResources(), false),
                Boolean.TRUE.equals(request.approvalRequired()), request.privilegedExportAllowed(),
                request.containmentOnly(), validFrom, request.expiresAt(), null, null, null,
                text(request.recordedBy()) != null ? text(request.recordedBy()) : delegator,
                request.recordedAt() != null ? request.recordedAt() : now,
                limit(request.maxItemsPerRequest(), "maxItemsPerRequest"),
                limit(request.maxItemsTotal(), "maxItemsTotal"));
    }

    /** The delegation revoked now by the person, unless it already ended. */
    public static AgentDelegation revoked(AgentDelegation delegation, String revokedBy, @Nullable String reason,
                                          Instant now) {
        if (delegation.revokedAt() != null || !now.isBefore(delegation.end())) {
            return delegation;
        }
        return new AgentDelegation(delegation.delegationId(), delegation.tenantId(), delegation.delegatorId(),
                delegation.agentId(), delegation.objectiveId(), delegation.objectiveFamily(),
                delegation.objectiveSummary(), delegation.allowedOperations(), delegation.allowedResources(),
                delegation.approvalRequired(), delegation.privilegedExportAllowed(), delegation.containmentOnly(),
                delegation.validFrom(), delegation.expiresAt(), now,
                required(revokedBy, "Who revokes is required"), text(reason), delegation.recordedBy(),
                delegation.recordedAt(), delegation.maxItemsPerRequest(), delegation.maxItemsTotal());
    }

    /** A quantity limit the delegation states: a positive number of items, or none. */
    private static Integer limit(@Nullable Integer value, String name) {
        if (value != null && value < 1) {
            throw new IllegalArgumentException(name + " must be at least 1 when it is stated");
        }
        return value;
    }

    /**
     * The delegation a request runs under among the person's delegations to the agent: the latest started one that
     * holds at the moment, else the latest started one at all.
     */
    public static Optional<AgentDelegation> current(Collection<AgentDelegation> delegations, Instant at) {
        Comparator<AgentDelegation> latest = Comparator.comparing(AgentDelegation::validFrom)
                .thenComparing(AgentDelegation::delegationId);
        return delegations.stream().filter(delegation -> delegation.validAt(at)).max(latest)
                .or(() -> delegations.stream().max(latest));
    }

    /**
     * The delegation an agent's request runs under, read the way the decision's own lookup reads it
     * ({@link RegistryDelegationRecordLookup}): the delegation the request names when it is the person's to that
     * agent, else the current one in the request's tenant, else (CF-13) the current one recorded without a tenant.
     */
    public static Optional<AgentDelegation> forRequest(DelegationRegistry registry, @Nullable String tenantId,
                                                       String delegatorId, String agentId,
                                                       @Nullable String delegationId, Instant at) {
        String named = text(delegationId);
        if (named != null) {
            Optional<AgentDelegation> found = registry.find(named)
                    .filter(delegation -> delegation.delegatorId().equals(text(delegatorId))
                            && delegation.agentId().equals(text(agentId)));
            if (found.isPresent()) {
                return found;
            }
        }
        String tenant = text(tenantId);
        Optional<AgentDelegation> current = registry.current(tenant, delegatorId, agentId, at);
        return current.isEmpty() && tenant != null ? registry.current(null, delegatorId, agentId, at) : current;
    }

    /** Whether the delegation belongs to the tenant ({@code null}: the single-tenant deployment). */
    public static boolean inTenant(AgentDelegation delegation, @Nullable String tenantId) {
        return AgentRegistrations.tenantKey(delegation.tenantId()).equals(AgentRegistrations.tenantKey(tenantId));
    }

    private static List<String> normalized(@Nullable List<String> values, boolean upperCase) {
        if (values == null) {
            return List.of();
        }
        Set<String> kept = new LinkedHashSet<>();
        for (String value : values) {
            String text = text(value);
            if (text != null) {
                kept.add(upperCase ? text.toUpperCase(Locale.ROOT) : text);
            }
        }
        if (kept.size() > LIST_LIMIT) {
            throw new IllegalArgumentException("A delegation may name at most " + LIST_LIMIT + " operations or resources");
        }
        return List.copyOf(kept);
    }

    private static String required(@Nullable String value, String message) {
        String text = text(value);
        if (text == null) {
            throw new IllegalArgumentException(message);
        }
        return text;
    }

    @Nullable
    static String text(@Nullable String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
