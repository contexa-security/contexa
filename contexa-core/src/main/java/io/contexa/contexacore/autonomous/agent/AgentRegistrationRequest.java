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

/**
 * An agent's registration as its identity provider states it (A1-6), for example from a SCIM provisioning call or an
 * Entra Agent ID event. A {@code null} value leaves what the registry holds unchanged.
 *
 * @param tenantId    the tenant, or {@code null} in a single-tenant deployment
 * @param agentId     the agent's identifier, as requests name it
 * @param displayName the name an operator reads
 * @param agentType   the kind of agent, in the identity provider's words
 * @param clientId    the OAuth2 client the agent's tokens are issued to
 * @param sponsorId   the person accountable for the agent
 * @param allowlisted whether the agent is approved; a registration is an approval unless it says otherwise
 */
public record AgentRegistrationRequest(
        String tenantId,
        String agentId,
        String displayName,
        String agentType,
        String clientId,
        String sponsorId,
        Boolean allowlisted) {
}
