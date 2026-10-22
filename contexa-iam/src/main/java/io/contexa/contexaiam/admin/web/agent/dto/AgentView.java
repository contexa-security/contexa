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
package io.contexa.contexaiam.admin.web.agent.dto;

import io.contexa.contexacore.autonomous.agent.AgentRegistration;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * An agent as the console shows it (A1-6, AM-1 and AM-2): the registry's values unchanged, with times in the
 * server's zone as the other console screens show them.
 */
public record AgentView(
        String tenantId,
        String agentId,
        String displayName,
        String agentType,
        String clientId,
        String sponsorId,
        String status,
        boolean allowlisted,
        String source,
        String subjectKind,
        LocalDateTime firstSeenAt,
        LocalDateTime lastSeenAt,
        LocalDateTime registeredAt,
        LocalDateTime deregisteredAt,
        String statusReason) {

    public static AgentView of(AgentRegistration registration) {
        return new AgentView(
                registration.tenantId(),
                registration.agentId(),
                registration.displayName(),
                registration.agentType(),
                registration.clientId(),
                registration.sponsorId(),
                registration.status() != null ? registration.status().name() : null,
                registration.allowlisted(),
                registration.source() != null ? registration.source().name() : null,
                registration.lastSubjectKind(),
                local(registration.firstSeenAt()),
                local(registration.lastSeenAt()),
                local(registration.registeredAt()),
                local(registration.deregisteredAt()),
                registration.statusReason());
    }

    private static LocalDateTime local(Instant instant) {
        return instant != null ? LocalDateTime.ofInstant(instant, ZoneId.systemDefault()) : null;
    }
}
