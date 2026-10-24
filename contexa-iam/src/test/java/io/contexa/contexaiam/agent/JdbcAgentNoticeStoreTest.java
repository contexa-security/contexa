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
import io.contexa.contexacore.autonomous.agent.InMemoryAgentNoticeStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A5-3, A5-2: the notices to the people accountable for agents are kept in the Contexa database as the
 * in-memory store keeps them. It runs only against the isolated database named by {@code CONTEXA_TEST_DB_URL}, in a
 * schema of its own that it drops afterwards.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class JdbcAgentNoticeStoreTest {

    private static final Instant NOW = Instant.parse("2026-10-24T01:00:00.123456Z");
    private static final String SCHEMA = "agent_notice_test";

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;

    @BeforeEach
    void setUp() throws Exception {
        Connection connection = DriverManager.getConnection(System.getenv("CONTEXA_TEST_DB_URL"),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
        dataSource = new SingleConnectionDataSource(connection, true);
        jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
        jdbc.execute("create schema " + SCHEMA);
        jdbc.execute("set search_path to " + SCHEMA);
        for (String statement : agentNoticeDdl()) {
            jdbc.execute(statement);
        }
    }

    @AfterEach
    void tearDown() {
        if (jdbc != null) {
            jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
        }
        if (dataSource != null) {
            dataSource.destroy();
        }
    }

    @Test
    void theDatabaseKeepsTheNoticesAsTheInMemoryStoreDoes() {
        Clock clock = Clock.fixed(NOW.plusSeconds(60), ZoneOffset.UTC);
        assertKeepsNotices(new JdbcAgentNoticeStore(jdbc, clock));
        assertKeepsNotices(new InMemoryAgentNoticeStore(clock));
    }

    private static void assertKeepsNotices(AgentNoticeStore store) {
        AgentNotice stopped = notice("n-1", null, "alice", NOW, AgentNotice.CONSOLE);
        store.save(stopped);
        store.save(notice("n-2", "tenant-acme", "carol", NOW.plusSeconds(1), "MAIL"));
        store.save(notice("n-3", null, "alice", NOW.plusSeconds(2), "MAIL"));
        // A channel's later delivery updates the notice kept.
        store.save(stopped.deliveredBy("MAIL"));

        assertThat(store.forRecipient("alice", 10)).extracting(AgentNotice::noticeId).containsExactly("n-3", "n-1");
        assertThat(store.forRecipient("alice", 10).get(1)).satisfies(notice -> {
            assertThat(notice.deliveredBy()).isEqualTo("MAIL");
            assertThat(notice.tenantId()).isNull();
            assertThat(notice.createdAt()).isEqualTo(NOW);
            assertThat(notice.delegationId()).isEqualTo("delegation-n-1");
            assertThat(notice.correlationId()).isEqualTo("req-n-1");
        });
        assertThat(store.list(null, 10)).extracting(AgentNotice::noticeId).containsExactly("n-3", "n-2", "n-1");
        assertThat(store.list("tenant-acme", 10)).extracting(AgentNotice::noticeId).containsExactly("n-2");
        assertThat(store.list(null, 1)).hasSize(1);

        assertThat(store.markRead("n-1", "bob")).isFalse();
        assertThat(store.markRead("n-1", "alice")).isTrue();
        assertThat(store.forRecipient("alice", 10).get(1).readAt()).isEqualTo(NOW.plusSeconds(60));
    }

    private static AgentNotice notice(String id, String tenant, String recipient, Instant at, String deliveredBy) {
        return new AgentNotice(id, AgentNotice.AGENT_STOPPED, tenant, recipient, "report-agent", "delegation-" + id,
                "The agent report-agent was stopped", "Contexa stopped the agent report-agent.", null, "req-" + id, at,
                deliveredBy, null);
    }

    /** The table and its indexes exactly as the canonical schema creates them. */
    private static List<String> agentNoticeDdl() throws Exception {
        String schema = new ClassPathResource("db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        Matcher table = Pattern.compile("(?is)create table if not exists agent_notice\\s*\\(.*?\\n\\);").matcher(schema);
        assertThat(table.find()).isTrue();
        Matcher indexes = Pattern.compile("(?is)create index if not exists \\S+\\s+on agent_notice\\s*\\([^;]*;")
                .matcher(schema);
        List<String> statements = new ArrayList<>();
        statements.add(table.group().replace(";", ""));
        while (indexes.find()) {
            statements.add(indexes.group().replace(";", ""));
        }
        assertThat(statements).hasSize(3);
        return statements;
    }
}
