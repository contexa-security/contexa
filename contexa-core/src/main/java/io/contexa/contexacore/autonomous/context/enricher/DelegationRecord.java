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
package io.contexa.contexacore.autonomous.context.enricher;

import java.time.Instant;
import java.util.List;

/**
 * A delegation as the host's business records keep it (A1-4, AG-1e): who delegated what work to which agent, within
 * which operations and resources, until when. {@code null} means the record does not state the fact; an empty list
 * states no operation or resource.
 *
 * @param delegationId            the record's own identifier, or {@code null}
 * @param delegatorId             the person who delegated the work, as the request's user ID names them
 * @param agentId                 the agent the work was delegated to
 * @param objectiveId             the delegated work's identifier, in the host's vocabulary
 * @param objectiveFamily         the kind of work, in the host's vocabulary
 * @param objectiveSummary        the work described for a reader
 * @param allowedOperations       the operations the agent may perform for this work
 * @param allowedResources        the resources the agent may touch for this work
 * @param approvalRequired        whether the delegator must approve before the work is done
 * @param privilegedExportAllowed whether the work may export privileged data
 * @param containmentOnly         whether the agent may only read or contain, not change or export anything
 * @param expiresAt               when the delegation ends
 * @param recordedBy              who wrote the record (A2-10): the delegator, an agent, an administrator; null when
 *                                the host does not say
 * @param recordedAt              when the record was written; null when the host does not say
 */
public record DelegationRecord(
        String delegationId,
        String delegatorId,
        String agentId,
        String objectiveId,
        String objectiveFamily,
        String objectiveSummary,
        List<String> allowedOperations,
        List<String> allowedResources,
        Boolean approvalRequired,
        Boolean privilegedExportAllowed,
        Boolean containmentOnly,
        Instant expiresAt,
        String recordedBy,
        Instant recordedAt) {

    public DelegationRecord {
        allowedOperations = allowedOperations == null ? List.of() : List.copyOf(allowedOperations);
        allowedResources = allowedResources == null ? List.of() : List.copyOf(allowedResources);
    }

    /** A record that does not say who wrote it or when (the form before A2-10). */
    public DelegationRecord(String delegationId, String delegatorId, String agentId, String objectiveId,
                            String objectiveFamily, String objectiveSummary, List<String> allowedOperations,
                            List<String> allowedResources, Boolean approvalRequired, Boolean privilegedExportAllowed,
                            Boolean containmentOnly, Instant expiresAt) {
        this(delegationId, delegatorId, agentId, objectiveId, objectiveFamily, objectiveSummary, allowedOperations,
                allowedResources, approvalRequired, privilegedExportAllowed, containmentOnly, expiresAt, null, null);
    }
}
