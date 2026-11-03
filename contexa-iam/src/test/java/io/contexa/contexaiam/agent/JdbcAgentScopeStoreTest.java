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

import io.contexa.contexacore.autonomous.agent.AgentScopeRestriction;
import io.contexa.contexacore.autonomous.agent.AgentScopeStore;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentScopeStore;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A5-4: the narrowed scopes are kept in the Contexa database as the in-memory store keeps them: a
 * narrowing only intersects, an ended one is replaced, and an account's deletion forgets them. It runs only against
 * the isolated database named by {@code CONTEXA_TEST_DB_URL}, in a schema of its own that it drops afterwards.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class JdbcAgentScopeStoreTest {

    private static final Instant NOW = Instant.parse("2026-10-24T03:00:00.123456Z");
    private static final String SCHEMA = "agent_scope_test";
    private static final String KEY = "alice::agent::report-agent";

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
        for (String statement : agentScopeDdl()) {
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
    void theDatabaseKeepsTheScopesAsTheInMemoryStoreDoes() {
        assertKeepsScopes(new JdbcAgentScopeStore(jdbc));
        assertKeepsScopes(new InMemoryAgentScopeStore());
    }

    private static void assertKeepsScopes(AgentScopeStore store) {
        AgentScopeRestriction first = scope(EnumSet.of(ActionFamily.READ, ActionFamily.WRITE), NOW,
                NOW.plus(Duration.ofHours(1)), "first");
        assertThat(store.merge(KEY, NOW, current -> current == null ? first : current.narrowedBy(first)))
                .isEqualTo(first);
        assertThat(store.find(KEY)).contains(first);

        AgentScopeRestriction later = scope(EnumSet.of(ActionFamily.READ, ActionFamily.EXPORT), NOW.plusSeconds(60),
                NOW.plus(Duration.ofHours(2)), "later");
        AgentScopeRestriction kept = store.merge(KEY, NOW.plusSeconds(60),
                current -> current == null ? later : current.narrowedBy(later));
        assertThat(kept.allowed()).containsExactly(ActionFamily.READ);
        assertThat(kept.until()).isEqualTo(NOW.plus(Duration.ofHours(2)));
        assertThat(kept.narrowedAt()).isEqualTo(NOW);
        assertThat(kept.reason()).isEqualTo("later");
        assertThat(store.find(KEY)).contains(kept);
        assertThat(store.active(NOW.plusSeconds(120), 10)).extracting(AgentScopeRestriction::subjectKey)
                .containsExactly(KEY);

        // Once ended, a new narrowing starts afresh.
        Instant afterEnd = NOW.plus(Duration.ofHours(3));
        AgentScopeRestriction fresh = scope(EnumSet.of(ActionFamily.WRITE), afterEnd, afterEnd.plusSeconds(600),
                "fresh");
        assertThat(store.active(afterEnd, 10)).isEmpty();
        assertThat(store.merge(KEY, afterEnd, current -> current == null ? fresh : current.narrowedBy(fresh))
                .allowed()).containsExactly(ActionFamily.WRITE);

        store.removeForUser("bob");
        assertThat(store.find(KEY)).isPresent();
        store.removeForUser("alice");
        assertThat(store.find(KEY)).isEmpty();
    }

    private static AgentScopeRestriction scope(EnumSet<ActionFamily> allowed, Instant at, Instant until,
                                               String reason) {
        return new AgentScopeRestriction(KEY, null, "alice", "report-agent", allowed, reason, "req-1", at, until);
    }

    /** The table and its indexes exactly as the canonical schema creates them. */
    private static List<String> agentScopeDdl() throws Exception {
        String schema = new ClassPathResource("db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        Matcher table = Pattern.compile("(?is)create table if not exists ctxa_agent_scope_restriction\\s*\\(.*?\\n\\);")
                .matcher(schema);
        assertThat(table.find()).isTrue();
        Matcher indexes = Pattern.compile("(?is)create index if not exists \\S+\\s+on ctxa_agent_scope_restriction\\s*\\([^;]*;")
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
