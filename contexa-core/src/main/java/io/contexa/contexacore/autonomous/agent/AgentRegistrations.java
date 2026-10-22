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
 * The rules of an agent registration's changes (A1-6), shared by every {@link AgentRegistry} so a database registry
 * keeps the same facts as the in-memory one.
 */
public final class AgentRegistrations {

    private AgentRegistrations() {
    }

    /** The first sighting registers the agent as observed; later ones move the last seen time forward only. */
    public static AgentRegistration observed(AgentRegistration current, AgentSighting sighting, Instant seenAt) {
        String agentId = sighting.agentId().trim();
        if (current == null) {
            return new AgentRegistration(text(sighting.tenantId()), agentId, null, null, text(sighting.clientId()), null,
                    AgentStatus.ACTIVE, false, AgentRegistrationSource.OBSERVED, text(sighting.subjectKind()),
                    seenAt, seenAt, null, null, null);
        }
        boolean latest = current.lastSeenAt() == null || !seenAt.isBefore(current.lastSeenAt());
        Instant firstSeenAt = current.firstSeenAt() == null || seenAt.isBefore(current.firstSeenAt())
                ? seenAt
                : current.firstSeenAt();
        return new AgentRegistration(current.tenantId(), current.agentId(), current.displayName(), current.agentType(),
                firstNonBlank(current.clientId(), sighting.clientId()), current.sponsorId(), current.status(),
                current.allowlisted(), current.source(),
                latest ? firstNonBlank(sighting.subjectKind(), current.lastSubjectKind()) : current.lastSubjectKind(),
                firstSeenAt, latest ? seenAt : current.lastSeenAt(), current.registeredAt(), current.deregisteredAt(),
                current.statusReason());
    }

    /**
     * A registration states what the identity provider knows and leaves the rest. A deregistered agent becomes active
     * again; a suspended one stays suspended, since a suspension is a security decision and not the provider's.
     */
    public static AgentRegistration registered(AgentRegistration current, AgentRegistrationRequest request, Instant now) {
        boolean allowlisted = request.allowlisted() == null || request.allowlisted();
        if (current == null) {
            return new AgentRegistration(text(request.tenantId()), request.agentId().trim(), text(request.displayName()),
                    text(request.agentType()), text(request.clientId()), text(request.sponsorId()), AgentStatus.ACTIVE,
                    allowlisted, AgentRegistrationSource.LIFECYCLE, null, null, null, now, null, null);
        }
        boolean reactivated = current.status() == AgentStatus.DEREGISTERED;
        return new AgentRegistration(current.tenantId(), current.agentId(),
                firstNonBlank(request.displayName(), current.displayName()),
                firstNonBlank(request.agentType(), current.agentType()),
                firstNonBlank(request.clientId(), current.clientId()),
                firstNonBlank(request.sponsorId(), current.sponsorId()),
                reactivated ? AgentStatus.ACTIVE : current.status(),
                allowlisted, AgentRegistrationSource.LIFECYCLE, current.lastSubjectKind(), current.firstSeenAt(),
                current.lastSeenAt(), now, reactivated ? null : current.deregisteredAt(),
                reactivated ? null : current.statusReason());
    }

    public static AgentRegistration deregistered(AgentRegistration current, String reason, Instant now) {
        return new AgentRegistration(current.tenantId(), current.agentId(), current.displayName(), current.agentType(),
                current.clientId(), current.sponsorId(), AgentStatus.DEREGISTERED, current.allowlisted(),
                current.source(), current.lastSubjectKind(), current.firstSeenAt(), current.lastSeenAt(),
                current.registeredAt(), now, text(reason));
    }

    public static AgentRegistration withSponsor(AgentRegistration current, String sponsorId) {
        return new AgentRegistration(current.tenantId(), current.agentId(), current.displayName(), current.agentType(),
                current.clientId(), text(sponsorId), current.status(), current.allowlisted(), current.source(),
                current.lastSubjectKind(), current.firstSeenAt(), current.lastSeenAt(), current.registeredAt(),
                current.deregisteredAt(), current.statusReason());
    }

    /** The key a tenant is stored under: its identifier, or an empty text for the single-tenant deployment. */
    public static String tenantKey(String tenantId) {
        String text = text(tenantId);
        return text != null ? text : "";
    }

    static void requireAgent(String agentId) {
        if (blank(agentId)) {
            throw new IllegalArgumentException("An agent identifier is required");
        }
    }

    static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String firstNonBlank(String preferred, String fallback) {
        String text = text(preferred);
        return text != null ? text : text(fallback);
    }

    private static String text(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
