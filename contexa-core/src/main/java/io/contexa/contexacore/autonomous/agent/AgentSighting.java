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

import java.time.Instant;

/**
 * An agent seen in a request (A1-6).
 *
 * @param tenantId    the request's tenant, or {@code null}
 * @param agentId     the agent the request names
 * @param subjectKind {@code DELEGATED_AGENT} or {@code AUTONOMOUS_AGENT}
 * @param clientId    the OAuth2 client of the agent's token, when the request carried one
 * @param seenAt      when the request was made
 */
public record AgentSighting(
        String tenantId,
        String agentId,
        String subjectKind,
        String clientId,
        Instant seenAt) {
}
