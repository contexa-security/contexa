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
 * What an agent registry holds of an agent that decides whether a client is an approved agent in service: where it
 * belongs, who it is, the client its tokens are issued to, whether it was approved through the life cycle interface and
 * its status. The rest of a registration (names, sponsor, times) takes no part in that decision.
 *
 * @param tenantId    the tenant the agent belongs to, or {@code null} in a single-tenant deployment
 * @param agentId     the agent's identifier
 * @param clientId    the OAuth2 client the agent's tokens are issued to, if any
 * @param status      its status; {@code null} for an agent the registry no longer holds
 * @param allowlisted whether it was approved through the life cycle interface rather than only observed
 */
public record AgentApproval(String tenantId, String agentId, String clientId, AgentStatus status, boolean allowlisted) {

    public static AgentApproval of(AgentRegistration registration) {
        return new AgentApproval(registration.tenantId(), registration.agentId(), registration.clientId(),
                registration.status(), registration.allowlisted());
    }

    /** The agent the registry no longer holds. */
    public static AgentApproval removed(String tenantId, String agentId) {
        return new AgentApproval(tenantId, agentId, null, null, false);
    }

    /** Whether the registry no longer holds the agent. */
    public boolean gone() {
        return status == null;
    }

    /** Whether the agent is approved and in service: what a client's token needs to be read as the agent's. */
    public boolean inService() {
        return allowlisted && status == AgentStatus.ACTIVE;
    }
}
