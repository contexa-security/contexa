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
 * An agent as Contexa knows it (A1-6, AG-11f, Microsoft Entra Agent ID sponsors, NIST IR 8596): who it is, the person
 * accountable for it, its status, and when it was first and last seen.
 *
 * @param tenantId        the tenant the agent belongs to, or {@code null} in a single-tenant deployment
 * @param agentId         the agent's identifier, as requests name it
 * @param displayName     the name an operator reads
 * @param agentType       the kind of agent, in the identity provider's words (for example its blueprint)
 * @param clientId        the OAuth2 client the agent's tokens are issued to
 * @param sponsorId       the person accountable for the agent: notified and asked when no delegating person is
 * @param status          its status
 * @param allowlisted     whether it was approved through the life cycle interface rather than only observed
 * @param source          how it came into the registry
 * @param lastSubjectKind the subject kind of its latest request ({@code DELEGATED_AGENT} or {@code AUTONOMOUS_AGENT})
 * @param firstSeenAt     its first request, or {@code null} when registered but not yet seen
 * @param lastSeenAt      its latest recorded request
 * @param registeredAt    its latest registration through the life cycle interface
 * @param deregisteredAt  when it was deregistered
 * @param statusReason    why its status last changed
 */
public record AgentRegistration(
        String tenantId,
        String agentId,
        String displayName,
        String agentType,
        String clientId,
        String sponsorId,
        AgentStatus status,
        boolean allowlisted,
        AgentRegistrationSource source,
        String lastSubjectKind,
        Instant firstSeenAt,
        Instant lastSeenAt,
        Instant registeredAt,
        Instant deregisteredAt,
        String statusReason) {
}
