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
package io.contexa.contexaiam.agent;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationSource;
import io.contexa.contexacore.autonomous.agent.AgentRegistrations;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.AgentSighting;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * The agent registry kept in the {@code agent_registration} table (A1-6). A request's sighting is one atomic upsert,
 * so concurrent requests of an agent never move its last seen time back; the rarer life cycle changes apply the shared
 * rules of {@link AgentRegistrations}. Lookups are cached briefly, since every agent request reads its sponsor.
 */
public class JdbcAgentRegistry implements AgentRegistry {

    private static final String COLUMNS = "tenant_key, agent_id, display_name, agent_type, client_id, sponsor_id, "
            + "status, allowlisted, source, last_subject_kind, first_seen_at, last_seen_at, registered_at, "
            + "deregistered_at, status_reason";

    private static final String OBSERVE_SQL = """
            insert into agent_registration (tenant_key, agent_id, client_id, status, allowlisted, source,
                                            last_subject_kind, first_seen_at, last_seen_at, updated_at)
            values (?, ?, ?, 'ACTIVE', false, 'OBSERVED', ?, ?, ?, ?)
            on conflict (tenant_key, agent_id) do update set
                client_id = coalesce(agent_registration.client_id, excluded.client_id),
                last_subject_kind = case
                    when agent_registration.last_seen_at is null
                         or excluded.last_seen_at >= agent_registration.last_seen_at
                    then coalesce(excluded.last_subject_kind, agent_registration.last_subject_kind)
                    else agent_registration.last_subject_kind end,
                first_seen_at = case
                    when agent_registration.first_seen_at is null
                         or excluded.first_seen_at < agent_registration.first_seen_at
                    then excluded.first_seen_at
                    else agent_registration.first_seen_at end,
                last_seen_at = greatest(coalesce(agent_registration.last_seen_at, excluded.last_seen_at),
                                        excluded.last_seen_at),
                updated_at = excluded.updated_at
            """;

    private static final String SAVE_SQL = """
            insert into agent_registration (tenant_key, agent_id, display_name, agent_type, client_id, sponsor_id,
                                            status, allowlisted, source, last_subject_kind, first_seen_at,
                                            last_seen_at, registered_at, deregistered_at, status_reason, updated_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_key, agent_id) do update set
                display_name = excluded.display_name,
                agent_type = excluded.agent_type,
                client_id = excluded.client_id,
                sponsor_id = excluded.sponsor_id,
                status = excluded.status,
                allowlisted = excluded.allowlisted,
                source = excluded.source,
                registered_at = excluded.registered_at,
                deregistered_at = excluded.deregistered_at,
                status_reason = excluded.status_reason,
                updated_at = excluded.updated_at
            """;

    private static final Duration LOOKUP_CACHE_TTL = Duration.ofSeconds(30);

    private final JdbcOperations jdbc;
    private final Clock clock;
    private final Cache<String, Optional<AgentRegistration>> lookups = Caffeine.newBuilder()
            .expireAfterWrite(LOOKUP_CACHE_TTL)
            .maximumSize(10_000)
            .build();

    public JdbcAgentRegistry(JdbcOperations jdbc) {
        this(jdbc, Clock.systemUTC());
    }

    public JdbcAgentRegistry(JdbcOperations jdbc, Clock clock) {
        if (jdbc == null) {
            throw new IllegalArgumentException("JDBC operations are required");
        }
        this.jdbc = jdbc;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public Optional<AgentRegistration> find(String tenantId, String agentId) {
        if (agentId == null || agentId.isBlank()) {
            return Optional.empty();
        }
        return lookups.get(cacheKey(tenantId, agentId), key -> read(tenantId, agentId));
    }

    @Override
    public List<AgentRegistration> list(String tenantId, int limit) {
        int rows = Math.max(0, limit);
        if (tenantId == null) {
            return jdbc.query("select " + COLUMNS + " from agent_registration "
                    + "order by last_seen_at desc nulls last, agent_id limit ?", ROW_MAPPER, rows);
        }
        return jdbc.query("select " + COLUMNS + " from agent_registration where tenant_key = ? "
                        + "order by last_seen_at desc nulls last, agent_id limit ?",
                ROW_MAPPER, AgentRegistrations.tenantKey(tenantId), rows);
    }

    @Override
    public AgentRegistration observe(AgentSighting sighting) {
        if (sighting == null || sighting.agentId() == null || sighting.agentId().isBlank()) {
            throw new IllegalArgumentException("An agent identifier is required");
        }
        String agentId = sighting.agentId().trim();
        Timestamp seenAt = Timestamp.from(sighting.seenAt() != null ? sighting.seenAt() : clock.instant());
        jdbc.update(OBSERVE_SQL, AgentRegistrations.tenantKey(sighting.tenantId()), agentId, text(sighting.clientId()),
                text(sighting.subjectKind()), seenAt, seenAt, Timestamp.from(clock.instant()));
        lookups.invalidate(cacheKey(sighting.tenantId(), agentId));
        return read(sighting.tenantId(), agentId).orElseThrow();
    }

    @Override
    public AgentRegistration register(AgentRegistrationRequest request) {
        if (request == null || request.agentId() == null || request.agentId().isBlank()) {
            throw new IllegalArgumentException("An agent identifier is required");
        }
        AgentRegistration current = read(request.tenantId(), request.agentId().trim()).orElse(null);
        return save(AgentRegistrations.registered(current, request, clock.instant()));
    }

    @Override
    public Optional<AgentRegistration> deregister(String tenantId, String agentId, String reason) {
        if (agentId == null || agentId.isBlank()) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        return read(tenantId, agentId.trim()).map(current -> save(AgentRegistrations.deregistered(current, reason, now)));
    }

    @Override
    public Optional<AgentRegistration> transferSponsor(String tenantId, String agentId, String sponsorId) {
        if (agentId == null || agentId.isBlank()) {
            return Optional.empty();
        }
        return read(tenantId, agentId.trim()).map(current -> save(AgentRegistrations.withSponsor(current, sponsorId)));
    }

    private AgentRegistration save(AgentRegistration registration) {
        jdbc.update(SAVE_SQL,
                AgentRegistrations.tenantKey(registration.tenantId()),
                registration.agentId(),
                registration.displayName(),
                registration.agentType(),
                registration.clientId(),
                registration.sponsorId(),
                registration.status().name(),
                registration.allowlisted(),
                registration.source().name(),
                registration.lastSubjectKind(),
                timestamp(registration.firstSeenAt()),
                timestamp(registration.lastSeenAt()),
                timestamp(registration.registeredAt()),
                timestamp(registration.deregisteredAt()),
                registration.statusReason(),
                Timestamp.from(clock.instant()));
        lookups.invalidate(cacheKey(registration.tenantId(), registration.agentId()));
        return read(registration.tenantId(), registration.agentId()).orElseThrow();
    }

    private Optional<AgentRegistration> read(String tenantId, String agentId) {
        List<AgentRegistration> rows = jdbc.query("select " + COLUMNS + " from agent_registration "
                + "where tenant_key = ? and agent_id = ?", ROW_MAPPER, AgentRegistrations.tenantKey(tenantId), agentId.trim());
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    private static final RowMapper<AgentRegistration> ROW_MAPPER = JdbcAgentRegistry::mapRow;

    private static AgentRegistration mapRow(ResultSet rs, int rowNum) throws SQLException {
        String tenantKey = rs.getString("tenant_key");
        return new AgentRegistration(
                tenantKey == null || tenantKey.isEmpty() ? null : tenantKey,
                rs.getString("agent_id"),
                rs.getString("display_name"),
                rs.getString("agent_type"),
                rs.getString("client_id"),
                rs.getString("sponsor_id"),
                AgentStatus.valueOf(rs.getString("status")),
                rs.getBoolean("allowlisted"),
                AgentRegistrationSource.valueOf(rs.getString("source")),
                rs.getString("last_subject_kind"),
                instant(rs.getTimestamp("first_seen_at")),
                instant(rs.getTimestamp("last_seen_at")),
                instant(rs.getTimestamp("registered_at")),
                instant(rs.getTimestamp("deregistered_at")),
                rs.getString("status_reason"));
    }

    private static String cacheKey(String tenantId, String agentId) {
        return AgentRegistrations.tenantKey(tenantId) + "\u0000" + agentId.trim();
    }

    private static Timestamp timestamp(Instant instant) {
        return instant != null ? Timestamp.from(instant) : null;
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp != null ? timestamp.toInstant() : null;
    }

    private static String text(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
