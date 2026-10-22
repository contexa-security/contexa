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

/**
 * What a request states about its delegation, for finding the delegation record (A1-4). Any value may be {@code null}
 * when the request does not state it.
 *
 * @param tenantId     the request's tenant or organization
 * @param delegatorId  the request's user ID: the delegating person for an agent acting for a person, the agent's own
 *                     subject for an agent acting on its own
 * @param agentId      the agent the request names
 * @param delegationId the delegation the request names (for example from a token or session)
 * @param objectiveId  the work the request names
 * @param requestedAt  when the request was made, for records that change over time
 */
public record DelegationRecordQuery(
        String tenantId,
        String delegatorId,
        String agentId,
        String delegationId,
        String objectiveId,
        Instant requestedAt) {
}
