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

import io.contexa.contexacore.autonomous.agent.AgentRegistrations;
import io.contexa.contexacore.autonomous.agent.AgentScopeRestriction;
import io.contexa.contexacore.autonomous.agent.AgentScopeStore;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.jdbc.core.JdbcOperations;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

/**
 * The narrowed scopes of agents kept in the Contexa database (table {@code agent_scope_restriction}, docs/agent A5-4).
 * A narrowing is a compare-and-set on the row it read, so two decisions narrowing the same agent at once both apply
 * and neither widens the other.
 */
public class JdbcAgentScopeStore implements AgentScopeStore {

    static final int ATTEMPTS = 5;
    private static final String COLUMNS = "subject_key, tenant_key, user_id, agent_id, allowed, reason, "
            + "correlation_id, narrowed_at, until_at";

    private final JdbcOperations jdbc;

    public JdbcAgentScopeStore(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<AgentScopeRestriction> find(String subjectKey) {
        if (subjectKey == null) {
            return Optional.empty();
        }
        return jdbc.query("select " + COLUMNS + " from agent_scope_restriction where subject_key = ?",
                JdbcAgentScopeStore::scope, subjectKey).stream().findFirst();
    }

    @Override
    public AgentScopeRestriction merge(String subjectKey, Instant now, UnaryOperator<AgentScopeRestriction> narrowing) {
        for (int attempt = 0; attempt < ATTEMPTS; attempt++) {
            Optional<AgentScopeRestriction> stored = find(subjectKey);
            AgentScopeRestriction current = stored.filter(scope -> scope.activeAt(now)).orElse(null);
            AgentScopeRestriction next = narrowing.apply(current);
            if (stored.isEmpty()) {
                if (jdbc.update("insert into agent_scope_restriction (" + COLUMNS + ") values (?, ?, ?, ?, ?, ?, ?, "
                        + "?, ?) on conflict (subject_key) do nothing", next.subjectKey(),
                        AgentRegistrations.tenantKey(next.tenantId()), next.userId(), next.agentId(),
                        names(next.allowed()), next.reason(), truncate(next.correlationId()),
                        Timestamp.from(next.narrowedAt()), Timestamp.from(next.until())) == 1) {
                    return next;
                }
                continue;
            }
            AgentScopeRestriction read = stored.get();
            if (jdbc.update("update agent_scope_restriction set allowed = ?, reason = ?, correlation_id = ?, "
                            + "narrowed_at = ?, until_at = ? where subject_key = ? and allowed = ? and until_at = ?",
                    names(next.allowed()), next.reason(), truncate(next.correlationId()),
                    Timestamp.from(next.narrowedAt()), Timestamp.from(next.until()), subjectKey,
                    names(read.allowed()), Timestamp.from(read.until())) == 1) {
                return next;
            }
        }
        throw new ConcurrencyFailureException("The narrowed scope of " + subjectKey + " kept changing");
    }

    @Override
    public List<AgentScopeRestriction> active(Instant now, int limit) {
        return jdbc.query("select " + COLUMNS + " from agent_scope_restriction where until_at > ? "
                + "order by until_at limit ?", JdbcAgentScopeStore::scope, Timestamp.from(now), Math.max(0, limit));
    }

    @Override
    public void removeForUser(String userId) {
        if (userId != null) {
            jdbc.update("delete from agent_scope_restriction where user_id = ?", userId);
        }
    }

    private static AgentScopeRestriction scope(ResultSet row, int number) throws SQLException {
        String tenantKey = row.getString("tenant_key");
        return new AgentScopeRestriction(row.getString("subject_key"),
                tenantKey == null || tenantKey.isEmpty() ? null : tenantKey, row.getString("user_id"),
                row.getString("agent_id"), families(row.getString("allowed")), row.getString("reason"),
                row.getString("correlation_id"), row.getTimestamp("narrowed_at").toInstant(),
                row.getTimestamp("until_at").toInstant());
    }

    private static String names(Set<ActionFamily> allowed) {
        return allowed.stream().map(Enum::name).sorted().collect(Collectors.joining(","));
    }

    private static Set<ActionFamily> families(String names) {
        EnumSet<ActionFamily> allowed = EnumSet.noneOf(ActionFamily.class);
        if (names != null && !names.isBlank()) {
            Arrays.stream(names.split(",")).map(String::trim).filter(name -> !name.isEmpty())
                    .map(ActionFamily::valueOf).forEach(allowed::add);
        }
        return allowed;
    }

    private static String truncate(String value) {
        return value != null && value.length() > 160 ? value.substring(0, 160) : value;
    }
}
