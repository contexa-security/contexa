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

import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

/**
 * The approved agents of the agent registry (A1-2, AG-12b): a client is an agent when the registry holds it as
 * allowlisted through the life cycle interface and in service. An agent only observed in requests, registered as not
 * approved, suspended or deregistered is not one. A registry that cannot answer names no agent, so a token it cannot
 * vouch for is refused rather than admitted.
 */
@Slf4j
public class RegistryAgentClientDirectory implements AgentClientDirectory {

    private final AgentRegistry registry;

    public RegistryAgentClientDirectory(AgentRegistry registry) {
        this.registry = registry;
    }

    @Override
    public Optional<String> activeAgentForClient(String tenantId, String clientId) {
        if (registry == null || AgentRegistrations.blank(clientId)) {
            return Optional.empty();
        }
        try {
            return registry.findByClientId(tenantId, clientId)
                    .filter(registration -> registration.allowlisted() && registration.status() == AgentStatus.ACTIVE)
                    .map(AgentRegistration::agentId);
        } catch (RuntimeException e) {
            log.error("Agent registry lookup failed; the client is not taken as an agent. clientId={}", clientId, e);
            return Optional.empty();
        }
    }

    @Override
    public boolean suspendedAgentClient(String tenantId, String clientId) {
        if (registry == null || AgentRegistrations.blank(clientId)) {
            return false;
        }
        try {
            return registry.findByClientId(tenantId, clientId)
                    .filter(registration -> registration.status() == AgentStatus.SUSPENDED)
                    .isPresent();
        } catch (RuntimeException e) {
            log.error("Agent registry lookup failed; the client's suspension is not known. clientId={}", clientId, e);
            return false;
        }
    }
}
