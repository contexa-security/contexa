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

import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.AgentDelegations;
import io.contexa.contexacore.autonomous.agent.AgentRegistrations;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The delegations kept in the {@code ctxa_agent_delegation_record} table (docs/agent OC-1). The rules are the shared ones of
 * {@link AgentDelegations}; a revocation is one conditional update, so two revocations keep the first.
 */
public class JdbcDelegationRegistry implements DelegationRegistry {

    private static final String COLUMNS = "delegation_id, tenant_key, delegator_id, agent_id, objective_id, "
            + "objective_family, objective_summary, allowed_operations, allowed_resources, approval_required, "
            + "privileged_export_allowed, containment_only, valid_from, expires_at, revoked_at, revoked_by, "
            + "revoke_reason, recorded_by, recorded_at, max_items_per_request, max_items_total";

    private static final String SEPARATOR = "\n";

    private final JdbcOperations jdbc;
    private final Duration maxValidity;
    private final Clock clock;

    public JdbcDelegationRegistry(JdbcOperations jdbc) {
        this(jdbc, null, Clock.systemUTC());
    }

    public JdbcDelegationRegistry(JdbcOperations jdbc, @Nullable Duration maxValidity, @Nullable Clock clock) {
        if (jdbc == null) {
            throw new IllegalArgumentException("A JDBC connection is required");
        }
        this.jdbc = jdbc;
        this.maxValidity = maxValidity;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public AgentDelegation record(AgentDelegationRequest request) {
        AgentDelegation delegation = AgentDelegations.newDelegation(UUID.randomUUID().toString(), request,
                maxValidity, clock.instant());
        jdbc.update("insert into ctxa_agent_delegation_record (" + COLUMNS + ") "
                        + "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                delegation.delegationId(), AgentRegistrations.tenantKey(delegation.tenantId()),
                delegation.delegatorId(), delegation.agentId(), delegation.objectiveId(),
                delegation.objectiveFamily(), delegation.objectiveSummary(), joined(delegation.allowedOperations()),
                joined(delegation.allowedResources()), delegation.approvalRequired(),
                delegation.privilegedExportAllowed(), delegation.containmentOnly(), timestamp(delegation.validFrom()),
                timestamp(delegation.expiresAt()), null, null, null, delegation.recordedBy(),
                timestamp(delegation.recordedAt()), delegation.maxItemsPerRequest(), delegation.maxItemsTotal());
        return delegation;
    }

    @Override
    public Optional<AgentDelegation> find(String delegationId) {
        String id = text(delegationId);
        if (id == null) {
            return Optional.empty();
        }
        return jdbc.query("select " + COLUMNS + " from ctxa_agent_delegation_record where delegation_id = ?",
                JdbcDelegationRegistry::delegation, id).stream().findFirst();
    }

    @Override
    public Optional<AgentDelegation> current(@Nullable String tenantId, String delegatorId, String agentId,
                                             Instant at) {
        String delegator = text(delegatorId);
        String agent = text(agentId);
        if (delegator == null || agent == null) {
            return Optional.empty();
        }
        Instant moment = at != null ? at : clock.instant();
        Timestamp when = timestamp(moment);
        List<AgentDelegation> holding = jdbc.query("select " + COLUMNS + " from ctxa_agent_delegation_record "
                        + "where tenant_key = ? and delegator_id = ? and agent_id = ? and valid_from <= ? "
                        + "and expires_at > ? and (revoked_at is null or revoked_at > ?) "
                        + "order by valid_from desc, delegation_id desc limit 1",
                JdbcDelegationRegistry::delegation, AgentRegistrations.tenantKey(tenantId), delegator, agent, when,
                when, when);
        if (!holding.isEmpty()) {
            return Optional.of(holding.get(0));
        }
        return jdbc.query("select " + COLUMNS + " from ctxa_agent_delegation_record "
                        + "where tenant_key = ? and delegator_id = ? and agent_id = ? "
                        + "order by valid_from desc, delegation_id desc limit 1",
                JdbcDelegationRegistry::delegation, AgentRegistrations.tenantKey(tenantId), delegator, agent)
                .stream().findFirst();
    }

    @Override
    public List<AgentDelegation> list(@Nullable String tenantId, @Nullable String delegatorId,
                                      @Nullable String agentId, int limit) {
        StringBuilder sql = new StringBuilder("select " + COLUMNS + " from ctxa_agent_delegation_record where 1 = 1");
        List<Object> arguments = new ArrayList<>();
        if (tenantId != null) {
            sql.append(" and tenant_key = ?");
            arguments.add(AgentRegistrations.tenantKey(tenantId));
        }
        if (text(delegatorId) != null) {
            sql.append(" and delegator_id = ?");
            arguments.add(text(delegatorId));
        }
        if (text(agentId) != null) {
            sql.append(" and agent_id = ?");
            arguments.add(text(agentId));
        }
        sql.append(" order by valid_from desc, delegation_id limit ?");
        arguments.add(Math.max(0, limit));
        return jdbc.query(sql.toString(), JdbcDelegationRegistry::delegation, arguments.toArray());
    }

    @Override
    public Optional<AgentDelegation> revoke(String delegationId, String revokedBy, @Nullable String reason) {
        Optional<AgentDelegation> found = find(delegationId);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        AgentDelegation revoked = AgentDelegations.revoked(found.get(), revokedBy, reason, now);
        if (revoked != found.get()) {
            jdbc.update("update ctxa_agent_delegation_record set revoked_at = ?, revoked_by = ?, revoke_reason = ? "
                            + "where delegation_id = ? and revoked_at is null and expires_at > ?",
                    timestamp(now), revoked.revokedBy(), revoked.revokeReason(), revoked.delegationId(),
                    timestamp(now));
        }
        return find(delegationId);
    }

    @Override
    public int deleteByDelegator(String delegatorId) {
        String delegator = text(delegatorId);
        if (delegator == null) {
            return 0;
        }
        return jdbc.update("delete from ctxa_agent_delegation_record where delegator_id = ?", delegator);
    }

    private static AgentDelegation delegation(ResultSet row, int index) throws SQLException {
        String tenantKey = row.getString("tenant_key");
        return new AgentDelegation(row.getString("delegation_id"),
                tenantKey == null || tenantKey.isEmpty() ? null : tenantKey,
                row.getString("delegator_id"), row.getString("agent_id"), row.getString("objective_id"),
                row.getString("objective_family"), row.getString("objective_summary"),
                split(row.getString("allowed_operations")), split(row.getString("allowed_resources")),
                row.getBoolean("approval_required"), nullableBoolean(row, "privileged_export_allowed"),
                nullableBoolean(row, "containment_only"), instant(row.getTimestamp("valid_from")),
                instant(row.getTimestamp("expires_at")), instant(row.getTimestamp("revoked_at")),
                row.getString("revoked_by"), row.getString("revoke_reason"), row.getString("recorded_by"),
                instant(row.getTimestamp("recorded_at")), nullableInteger(row, "max_items_per_request"),
                nullableInteger(row, "max_items_total"));
    }

    private static Integer nullableInteger(ResultSet row, String column) throws SQLException {
        int value = row.getInt(column);
        return row.wasNull() ? null : value;
    }

    private static Boolean nullableBoolean(ResultSet row, String column) throws SQLException {
        boolean value = row.getBoolean(column);
        return row.wasNull() ? null : value;
    }

    private static String joined(List<String> values) {
        return values == null || values.isEmpty() ? null : String.join(SEPARATOR, values);
    }

    private static List<String> split(String joined) {
        if (joined == null || joined.isBlank()) {
            return List.of();
        }
        return Arrays.stream(joined.split(SEPARATOR)).map(String::trim).filter(value -> !value.isEmpty()).toList();
    }

    private static Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private static String text(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
