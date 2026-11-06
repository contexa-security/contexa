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

import io.contexa.contexacore.autonomous.agent.AgentNotice;
import io.contexa.contexacore.autonomous.agent.AgentNoticeStore;
import io.contexa.contexacore.autonomous.agent.AgentRegistrations;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** The notices kept in the {@code ctxa_agent_notice} table (docs/agent A5-3, A5-2). */
public class JdbcAgentNoticeStore implements AgentNoticeStore {

    private static final String COLUMNS = "notice_id, kind, tenant_key, recipient_id, agent_id, delegation_id, "
            + "subject, message, link, correlation_id, created_at, delivered_by, read_at";

    private final JdbcOperations jdbc;
    private final Clock clock;

    public JdbcAgentNoticeStore(JdbcOperations jdbc) {
        this(jdbc, Clock.systemUTC());
    }

    public JdbcAgentNoticeStore(JdbcOperations jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @Override
    public AgentNotice save(AgentNotice notice) {
        jdbc.update("insert into ctxa_agent_notice (" + COLUMNS + ") values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                        + "on conflict (notice_id) do update set delivered_by = excluded.delivered_by, "
                        + "read_at = excluded.read_at",
                notice.noticeId(), notice.kind(), AgentRegistrations.tenantKey(notice.tenantId()),
                notice.recipientId(), notice.agentId(), notice.delegationId(), truncate(notice.subject(), 512),
                notice.message(), truncate(notice.link(), 1024), truncate(notice.correlationId(), 160),
                timestamp(notice.createdAt()), notice.deliveredBy(), timestamp(notice.readAt()));
        return notice;
    }

    @Override
    public List<AgentNotice> forRecipient(String recipientId, int limit) {
        return jdbc.query("select " + COLUMNS + " from ctxa_agent_notice where recipient_id = ? "
                + "order by created_at desc limit ?", JdbcAgentNoticeStore::notice, recipientId, Math.max(0, limit));
    }

    @Override
    public Optional<AgentNotice> find(String recipientId, String kind, String correlationId) {
        if (recipientId == null || kind == null || correlationId == null) {
            return Optional.empty();
        }
        return jdbc.query("select " + COLUMNS + " from ctxa_agent_notice where recipient_id = ? and kind = ? "
                        + "and correlation_id = ? order by created_at desc limit 1", JdbcAgentNoticeStore::notice,
                recipientId, kind, truncate(correlationId, 160)).stream().findFirst();
    }

    @Override
    public List<AgentNotice> list(@Nullable String tenantId, int limit) {
        if (tenantId == null) {
            return jdbc.query("select " + COLUMNS + " from ctxa_agent_notice order by created_at desc limit ?",
                    JdbcAgentNoticeStore::notice, Math.max(0, limit));
        }
        return jdbc.query("select " + COLUMNS + " from ctxa_agent_notice where tenant_key = ? "
                        + "order by created_at desc limit ?", JdbcAgentNoticeStore::notice,
                AgentRegistrations.tenantKey(tenantId), Math.max(0, limit));
    }

    @Override
    public void removeForRecipient(String recipientId) {
        if (recipientId != null) {
            jdbc.update("delete from ctxa_agent_notice where recipient_id = ?", recipientId);
        }
    }

    @Override
    public boolean markRead(String noticeId, String recipientId) {
        return jdbc.update("update ctxa_agent_notice set read_at = coalesce(read_at, ?) "
                + "where notice_id = ? and recipient_id = ?", timestamp(clock.instant()), noticeId, recipientId) > 0;
    }

    private static AgentNotice notice(ResultSet row, int number) throws SQLException {
        String tenantKey = row.getString("tenant_key");
        return new AgentNotice(row.getString("notice_id"), row.getString("kind"),
                tenantKey == null || tenantKey.isEmpty() ? null : tenantKey, row.getString("recipient_id"),
                row.getString("agent_id"), row.getString("delegation_id"), row.getString("subject"),
                row.getString("message"), row.getString("link"), row.getString("correlation_id"),
                instant(row.getTimestamp("created_at")), row.getString("delivered_by"),
                instant(row.getTimestamp("read_at")));
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
