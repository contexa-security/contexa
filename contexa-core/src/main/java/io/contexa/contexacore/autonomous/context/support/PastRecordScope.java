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
package io.contexa.contexacore.autonomous.context.support;

import java.util.List;
import java.util.Objects;

/**
 * Which past records a request is compared with (W3-18): the user's own allowed records stored for the retrieval
 * purpose, of the request's action family, outside the request's session (under any id it had, W2-8) and not held
 * back. The action family, not the protected method, is the scope, so another entry point of the same work is counted.
 * docs/agent A3-1, A3-2: the records of the request's tenant as the document authorization reads a tenant (a record of
 * no tenant or organization is bound to none), and of the request's subject: an agent's records for an agent's request,
 * no agent's records for a person's.
 *
 * @param userId             the requesting user
 * @param retrievalPurpose   the retrieval purpose the records were stored for
 * @param actionFamily       the request's action family
 * @param excludedSessionIds the ids of the request's session
 * @param tenantId           the request's tenant, or null
 * @param organizationId     the request's organization, or null
 * @param agentId            the agent of an agent's request, or null for a person's
 */
public record PastRecordScope(String userId, String retrievalPurpose, String actionFamily, List<String> excludedSessionIds,
                              String tenantId, String organizationId, String agentId) {

    public PastRecordScope {
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(actionFamily, "actionFamily");
        excludedSessionIds = excludedSessionIds == null ? List.of() : List.copyOf(excludedSessionIds);
    }

    /** A person's request of no tenant or organization. */
    public PastRecordScope(String userId, String retrievalPurpose, String actionFamily, List<String> excludedSessionIds) {
        this(userId, retrievalPurpose, actionFamily, excludedSessionIds, null, null, null);
    }
}
