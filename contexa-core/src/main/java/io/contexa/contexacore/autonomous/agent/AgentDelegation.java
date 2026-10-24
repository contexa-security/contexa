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
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.List;

/**
 * A delegation Contexa keeps (docs/agent OC-1): a person delegated work to an agent, within operations and resources,
 * for a period. It ends when it expires or is revoked; an ended delegation is kept, since its end is a fact a decision
 * weighs.
 *
 * @param delegationId            the delegation's identifier
 * @param tenantId                the tenant, or {@code null} for the single-tenant deployment
 * @param delegatorId             the person who delegated the work, as the requests' user ID names them
 * @param agentId                 the agent the work was delegated to
 * @param objectiveId             the delegated work's identifier, in the application's vocabulary, or null
 * @param objectiveFamily         the kind of work, an objective family the application declares, or null
 * @param objectiveSummary        the work described for a reader (text the delegator wrote), or null
 * @param allowedOperations       the operations allowed, as the {@code @Protectable} actions name them (READ, EXPORT)
 * @param allowedResources        the resources allowed: path patterns ({@code /api/projects/**}) or the application's
 *                                business identifiers
 * @param approvalRequired        whether the delegator must approve before the work is done
 * @param privilegedExportAllowed whether the work may export privileged data, or null when not stated
 * @param containmentOnly         whether the agent may only read or contain, or null when not stated
 * @param validFrom               when the delegation starts
 * @param expiresAt               when the delegation ends unless revoked earlier
 * @param revokedAt               when it was revoked, or null
 * @param revokedBy               who revoked it, or null
 * @param revokeReason            why it was revoked, or null
 * @param recordedBy              who wrote the record: the delegator, an administrator or an integration
 * @param recordedAt              when the record was written
 */
public record AgentDelegation(
        String delegationId,
        @Nullable String tenantId,
        String delegatorId,
        String agentId,
        @Nullable String objectiveId,
        @Nullable String objectiveFamily,
        @Nullable String objectiveSummary,
        List<String> allowedOperations,
        List<String> allowedResources,
        boolean approvalRequired,
        @Nullable Boolean privilegedExportAllowed,
        @Nullable Boolean containmentOnly,
        Instant validFrom,
        Instant expiresAt,
        @Nullable Instant revokedAt,
        @Nullable String revokedBy,
        @Nullable String revokeReason,
        String recordedBy,
        Instant recordedAt) {

    public AgentDelegation {
        allowedOperations = allowedOperations == null ? List.of() : List.copyOf(allowedOperations);
        allowedResources = allowedResources == null ? List.of() : List.copyOf(allowedResources);
    }

    /** When the delegation ends: its revocation when that came before its expiry, else its expiry. */
    public Instant end() {
        return revokedAt != null && revokedAt.isBefore(expiresAt) ? revokedAt : expiresAt;
    }

    /** Whether the delegation holds at the moment: started, not expired and not revoked. */
    public boolean validAt(Instant at) {
        return at != null && !at.isBefore(validFrom) && at.isBefore(end());
    }

    /** The delegation as a decision reads it; an ended delegation reads with its end. */
    public DelegationRecord toRecord() {
        return new DelegationRecord(delegationId, delegatorId, agentId, objectiveId, objectiveFamily, objectiveSummary,
                allowedOperations, allowedResources, approvalRequired, privilegedExportAllowed, containmentOnly, end(),
                recordedBy, recordedAt);
    }
}
