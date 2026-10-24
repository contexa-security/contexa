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

import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.AgentRegistrations;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * The confirmations of agents' requests kept in the Contexa database (table {@code agent_confirmation}, docs/agent
 * A5-2). A decision and the use of an approval are each one conditional update, so that two of them never both
 * succeed.
 */
public class JdbcAgentConfirmationStore implements AgentConfirmationStore {

    private static final String COLUMNS = "confirmation_id, tenant_key, subject_kind, user_id, agent_id, subject_key, "
            + "delegation_id, recipient_id, request_hash, request_method, request_target, trigger_kind, reason, "
            + "correlation_id, status, created_at, expires_at, decided_at, decided_by, decision_note, "
            + "authorization_id, used_at";

    private final JdbcOperations jdbc;

    public JdbcAgentConfirmationStore(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public AgentConfirmation save(AgentConfirmation confirmation) {
        jdbc.update("insert into agent_confirmation (" + COLUMNS + ") values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                        + "?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict (confirmation_id) do update set "
                        + "status = excluded.status, expires_at = excluded.expires_at, "
                        + "decided_at = excluded.decided_at, decided_by = excluded.decided_by, "
                        + "decision_note = excluded.decision_note, authorization_id = excluded.authorization_id, "
                        + "used_at = excluded.used_at",
                confirmation.confirmationId(), AgentRegistrations.tenantKey(confirmation.tenantId()),
                confirmation.subjectKind(), confirmation.userId(), confirmation.agentId(), confirmation.subjectKey(),
                confirmation.delegationId(), confirmation.recipientId(), confirmation.requestHash(),
                truncate(confirmation.method(), 16), truncate(confirmation.target(), 2048), confirmation.trigger(),
                confirmation.reason(), truncate(confirmation.correlationId(), 160), confirmation.status().name(),
                timestamp(confirmation.createdAt()), timestamp(confirmation.expiresAt()),
                timestamp(confirmation.decidedAt()), confirmation.decidedBy(), confirmation.decisionNote(),
                confirmation.authorizationId(), timestamp(confirmation.usedAt()));
        return confirmation;
    }

    @Override
    public Optional<AgentConfirmation> find(String confirmationId) {
        if (confirmationId == null) {
            return Optional.empty();
        }
        return jdbc.query("select " + COLUMNS + " from agent_confirmation where confirmation_id = ?",
                JdbcAgentConfirmationStore::confirmation, confirmationId).stream().findFirst();
    }

    @Override
    public Optional<AgentConfirmation> latest(String subjectKey, String requestHash, AgentConfirmation.Status status) {
        return jdbc.query("select " + COLUMNS + " from agent_confirmation where subject_key = ? and request_hash = ? "
                        + "and status = ? order by created_at desc limit 1", JdbcAgentConfirmationStore::confirmation,
                subjectKey, requestHash, status.name()).stream().findFirst();
    }

    @Override
    public boolean transition(AgentConfirmation next, AgentConfirmation.Status expected) {
        return jdbc.update("update agent_confirmation set status = ?, expires_at = ?, decided_at = ?, decided_by = ?, "
                        + "decision_note = ?, authorization_id = ?, used_at = ? where confirmation_id = ? "
                        + "and status = ?", next.status().name(), timestamp(next.expiresAt()),
                timestamp(next.decidedAt()), next.decidedBy(), next.decisionNote(), next.authorizationId(),
                timestamp(next.usedAt()), next.confirmationId(), expected.name()) == 1;
    }

    @Override
    public boolean markUsed(String confirmationId, String requestHash, Instant usedAt) {
        return jdbc.update("update agent_confirmation set status = ?, used_at = ? where confirmation_id = ? "
                        + "and request_hash = ? and status = ?", AgentConfirmation.Status.USED.name(),
                timestamp(usedAt), confirmationId, requestHash, AgentConfirmation.Status.APPROVED.name()) == 1;
    }

    @Override
    public List<AgentConfirmation> forRecipient(String recipientId, int limit) {
        return jdbc.query("select " + COLUMNS + " from agent_confirmation where recipient_id = ? "
                        + "order by created_at desc limit ?", JdbcAgentConfirmationStore::confirmation, recipientId,
                Math.max(0, limit));
    }

    @Override
    public List<AgentConfirmation> overdue(Instant now, int limit) {
        return jdbc.query("select " + COLUMNS + " from agent_confirmation where status in (?, ?) and expires_at <= ? "
                        + "order by expires_at limit ?", JdbcAgentConfirmationStore::confirmation,
                AgentConfirmation.Status.PENDING.name(), AgentConfirmation.Status.APPROVED.name(), timestamp(now),
                Math.max(0, limit));
    }

    @Override
    public void removeForUser(String userId) {
        if (userId != null) {
            jdbc.update("delete from agent_confirmation where user_id = ? or recipient_id = ?", userId, userId);
        }
    }

    @Override
    public List<AgentConfirmation> list(@Nullable String tenantId, int limit) {
        if (tenantId == null) {
            return jdbc.query("select " + COLUMNS + " from agent_confirmation order by created_at desc limit ?",
                    JdbcAgentConfirmationStore::confirmation, Math.max(0, limit));
        }
        return jdbc.query("select " + COLUMNS + " from agent_confirmation where tenant_key = ? "
                        + "order by created_at desc limit ?", JdbcAgentConfirmationStore::confirmation,
                AgentRegistrations.tenantKey(tenantId), Math.max(0, limit));
    }

    private static AgentConfirmation confirmation(ResultSet row, int number) throws SQLException {
        String tenantKey = row.getString("tenant_key");
        return new AgentConfirmation(row.getString("confirmation_id"),
                tenantKey == null || tenantKey.isEmpty() ? null : tenantKey, row.getString("subject_kind"),
                row.getString("user_id"), row.getString("agent_id"), row.getString("delegation_id"),
                row.getString("recipient_id"), row.getString("request_hash"), row.getString("request_method"),
                row.getString("request_target"), row.getString("trigger_kind"), row.getString("reason"),
                row.getString("correlation_id"), AgentConfirmation.Status.valueOf(row.getString("status")),
                instant(row.getTimestamp("created_at")), instant(row.getTimestamp("expires_at")),
                instant(row.getTimestamp("decided_at")), row.getString("decided_by"),
                row.getString("decision_note"), row.getString("authorization_id"),
                instant(row.getTimestamp("used_at")));
    }

    @Nullable
    private static String truncate(@Nullable String value, int length) {
        return value != null && value.length() > length ? value.substring(0, length) : value;
    }

    @Nullable
    private static Timestamp timestamp(@Nullable Instant instant) {
        return instant != null ? Timestamp.from(instant) : null;
    }

    @Nullable
    private static Instant instant(@Nullable Timestamp timestamp) {
        return timestamp != null ? timestamp.toInstant() : null;
    }
}
