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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

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

    /**
     * docs/agent A5-3: a security decision or an operator stopped the agent; a deregistered agent stays deregistered,
     * since its identity provider removed it.
     */
    public static AgentRegistration suspended(AgentRegistration current, String reason) {
        if (current.status() == AgentStatus.DEREGISTERED) {
            return current;
        }
        return withStatus(current, AgentStatus.SUSPENDED, reason);
    }

    /** docs/agent A5-3: a suspension ended; any other status stays. */
    public static AgentRegistration resumed(AgentRegistration current, String reason) {
        if (current.status() != AgentStatus.SUSPENDED) {
            return current;
        }
        return withStatus(current, AgentStatus.ACTIVE, reason);
    }

    private static AgentRegistration withStatus(AgentRegistration current, AgentStatus status, String reason) {
        return new AgentRegistration(current.tenantId(), current.agentId(), current.displayName(), current.agentType(),
                current.clientId(), current.sponsorId(), status, current.allowlisted(), current.source(),
                current.lastSubjectKind(), current.firstSeenAt(), current.lastSeenAt(), current.registeredAt(),
                current.deregisteredAt(), text(reason));
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

    /**
     * The agent's registration as a request in the tenant reads it: the tenant's own, else (CF-13) the single-tenant
     * registration a token or account naming no tenant was admitted under, as the event publisher reads it.
     * <p>
     * A row of the tenant that only observed the agent (the sighting the engine records after its first request)
     * knows no sponsor, client or allow list entry, so it does not stand in for the single-tenant registration of the
     * same agent (CF-33): the registration speaks for the agent, seen in the tenant, and the stricter status of the
     * two stays, since a suspension is recorded on the row of the tenant the agent was stopped in.
     */
    public static Optional<AgentRegistration> find(AgentRegistry registry, String tenantId, String agentId) {
        String tenant = text(tenantId);
        Optional<AgentRegistration> found = registry.find(tenant, agentId);
        if (tenant == null) {
            return found;
        }
        if (found.isEmpty()) {
            return registry.find(null, agentId);
        }
        if (found.get().source() != AgentRegistrationSource.OBSERVED) {
            return found;
        }
        Optional<AgentRegistration> registered = registry.find(null, agentId)
                .filter(registration -> registration.source() == AgentRegistrationSource.LIFECYCLE);
        return registered.isPresent() ? Optional.of(seenIn(found.get(), registered.get())) : found;
    }

    /** The registration, seen in the tenant: its facts, the tenant's sightings, and the stricter status of the two. */
    private static AgentRegistration seenIn(AgentRegistration observed, AgentRegistration registered) {
        boolean observedStricter = observed.status().ordinal() > registered.status().ordinal();
        AgentRegistration stricter = observedStricter ? observed : registered;
        return new AgentRegistration(observed.tenantId(), registered.agentId(), registered.displayName(),
                registered.agentType(), firstNonBlank(registered.clientId(), observed.clientId()),
                registered.sponsorId(), stricter.status(), registered.allowlisted(), registered.source(),
                firstNonBlank(observed.lastSubjectKind(), registered.lastSubjectKind()), observed.firstSeenAt(),
                observed.lastSeenAt(), registered.registeredAt(), stricter.deregisteredAt(), stricter.statusReason());
    }

    /**
     * The client's agent in each tenant among the registrations, chosen as {@link AgentRegistry#findByClientId} chooses
     * in one tenant: the agent whose tokens are issued to the client (the first by identifier), else the agent whose
     * identifier is the client's. Tenants in the order of their keys, the single-tenant deployment's first.
     */
    public static List<AgentRegistration> eachTenantsForClient(Collection<AgentRegistration> registrations,
                                                                 String clientId) {
        Map<String, List<AgentRegistration>> byTenant = new TreeMap<>();
        for (AgentRegistration registration : registrations) {
            if (clientId.equals(registration.clientId()) || clientId.equals(registration.agentId())) {
                byTenant.computeIfAbsent(tenantKey(registration.tenantId()), key -> new ArrayList<>()).add(registration);
            }
        }
        List<AgentRegistration> found = new ArrayList<>();
        for (List<AgentRegistration> inTenant : byTenant.values()) {
            inTenant.stream()
                    .filter(registration -> clientId.equals(registration.clientId()))
                    .min(Comparator.comparing(AgentRegistration::agentId))
                    .or(() -> inTenant.stream().filter(registration -> clientId.equals(registration.agentId())).findFirst())
                    .ifPresent(found::add);
        }
        return List.copyOf(found);
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
