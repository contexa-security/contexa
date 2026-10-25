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

/**
 * A delegation to record (docs/agent OC-1). The delegator, the agent and the end are required; the start and the
 * record's time default to now and its writer to the delegator. An integration that copies delegations from the
 * application's own records states who wrote each and when.
 */
public record AgentDelegationRequest(
        @Nullable String tenantId,
        String delegatorId,
        String agentId,
        @Nullable String objectiveId,
        @Nullable String objectiveFamily,
        @Nullable String objectiveSummary,
        @Nullable List<String> allowedOperations,
        @Nullable List<String> allowedResources,
        @Nullable Boolean approvalRequired,
        @Nullable Boolean privilegedExportAllowed,
        @Nullable Boolean containmentOnly,
        @Nullable Instant validFrom,
        Instant expiresAt,
        @Nullable String recordedBy,
        @Nullable Instant recordedAt,
        @Nullable Integer maxItemsPerRequest,
        @Nullable Integer maxItemsTotal) {

    /** A delegation that states no quantity limit (the form before RL-6). */
    public AgentDelegationRequest(@Nullable String tenantId, String delegatorId, String agentId,
                                  @Nullable String objectiveId, @Nullable String objectiveFamily,
                                  @Nullable String objectiveSummary, @Nullable List<String> allowedOperations,
                                  @Nullable List<String> allowedResources, @Nullable Boolean approvalRequired,
                                  @Nullable Boolean privilegedExportAllowed, @Nullable Boolean containmentOnly,
                                  @Nullable Instant validFrom, Instant expiresAt, @Nullable String recordedBy,
                                  @Nullable Instant recordedAt) {
        this(tenantId, delegatorId, agentId, objectiveId, objectiveFamily, objectiveSummary, allowedOperations,
                allowedResources, approvalRequired, privilegedExportAllowed, containmentOnly, validFrom, expiresAt,
                recordedBy, recordedAt, null, null);
    }
}
