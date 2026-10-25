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
package io.contexa.contexaiam.admin.web.agent.controller;

import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;

import java.time.Instant;
import java.util.List;

/** The bodies of the delegation APIs (docs/agent OC-1). */
public final class AgentDelegationViews {

    private AgentDelegationViews() {
    }

    /**
     * A delegation to record. The delegation API takes the delegator from the signed-in person and ignores
     * {@code delegatorId}, {@code tenantId}, {@code recordedBy} and {@code recordedAt}; the admin API takes them as the
     * application's records state them.
     */
    public record DelegationBody(String tenantId, String delegatorId, String agentId, String objectiveId,
                                 String objectiveFamily, String objectiveSummary, List<String> allowedOperations,
                                 List<String> allowedResources, Boolean approvalRequired,
                                 Boolean privilegedExportAllowed, Boolean containmentOnly, Instant validFrom,
                                 Instant expiresAt, String recordedBy, Instant recordedAt, Integer maxItemsPerRequest,
                                 Integer maxItemsTotal) {

        /** A body that states no quantity limit (the form before RL-6). */
        public DelegationBody(String tenantId, String delegatorId, String agentId, String objectiveId,
                              String objectiveFamily, String objectiveSummary, List<String> allowedOperations,
                              List<String> allowedResources, Boolean approvalRequired, Boolean privilegedExportAllowed,
                              Boolean containmentOnly, Instant validFrom, Instant expiresAt, String recordedBy,
                              Instant recordedAt) {
            this(tenantId, delegatorId, agentId, objectiveId, objectiveFamily, objectiveSummary, allowedOperations,
                    allowedResources, approvalRequired, privilegedExportAllowed, containmentOnly, validFrom, expiresAt,
                    recordedBy, recordedAt, null, null);
        }

        public AgentDelegationRequest toRequest() {
            return new AgentDelegationRequest(tenantId, delegatorId, agentId, objectiveId, objectiveFamily,
                    objectiveSummary, allowedOperations, allowedResources, approvalRequired, privilegedExportAllowed,
                    containmentOnly, validFrom, expiresAt, recordedBy, recordedAt, maxItemsPerRequest, maxItemsTotal);
        }
    }

    /** Why a delegation is revoked. */
    public record RevokeBody(String reason) {
    }

    /** A delegation as the APIs return it, with whether it holds now. */
    public record DelegationView(String delegationId, String tenantId, String delegatorId, String agentId,
                                 String objectiveId, String objectiveFamily, String objectiveSummary,
                                 List<String> allowedOperations, List<String> allowedResources,
                                 boolean approvalRequired, Boolean privilegedExportAllowed, Boolean containmentOnly,
                                 Instant validFrom, Instant expiresAt, Instant revokedAt, String revokedBy,
                                 String revokeReason, String recordedBy, Instant recordedAt, Integer maxItemsPerRequest,
                                 Integer maxItemsTotal, String state) {

        public static DelegationView of(AgentDelegation delegation, Instant now) {
            return new DelegationView(delegation.delegationId(), delegation.tenantId(), delegation.delegatorId(),
                    delegation.agentId(), delegation.objectiveId(), delegation.objectiveFamily(),
                    delegation.objectiveSummary(), delegation.allowedOperations(), delegation.allowedResources(),
                    delegation.approvalRequired(), delegation.privilegedExportAllowed(), delegation.containmentOnly(),
                    delegation.validFrom(), delegation.expiresAt(), delegation.revokedAt(), delegation.revokedBy(),
                    delegation.revokeReason(), delegation.recordedBy(), delegation.recordedAt(),
                    delegation.maxItemsPerRequest(), delegation.maxItemsTotal(), state(delegation, now));
        }

        /** VALID, NOT_STARTED, EXPIRED or REVOKED. */
        static String state(AgentDelegation delegation, Instant now) {
            if (delegation.revokedAt() != null && !now.isBefore(delegation.revokedAt())) {
                return "REVOKED";
            }
            if (now.isBefore(delegation.validFrom())) {
                return "NOT_STARTED";
            }
            return now.isBefore(delegation.expiresAt()) ? "VALID" : "EXPIRED";
        }
    }
}
