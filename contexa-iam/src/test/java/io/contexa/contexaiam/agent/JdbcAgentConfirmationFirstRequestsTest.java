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
import io.contexa.contexacore.autonomous.agent.InMemoryAgentConfirmationStore;
import io.contexa.contexacore.testsupport.AgentConfirmationFirstRequestsContract;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The first requests of one agent that arrive together mail the person once on the database the confirmations are
 * kept in, as with the in-memory store, and the two stores tell the same whether another confirmation waited when one
 * is saved. It runs only against the isolated database named by {@code CONTEXA_TEST_DB_URL}, in a database of its own
 * that it drops afterwards.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class JdbcAgentConfirmationFirstRequestsTest {

    private static final Instant NOW = Instant.parse("2026-10-24T02:00:00.123456Z");

    private PostgresTestDatabase database;
    private JdbcAgentConfirmationStore store;

    @BeforeEach
    void setUp() throws Exception {
        database = PostgresTestDatabase.empty();
        JdbcTemplate jdbc = database.jdbcTemplate();
        for (String statement : agentConfirmationDdl()) {
            jdbc.execute(statement);
        }
        store = new JdbcAgentConfirmationStore(jdbc);
    }

    @AfterEach
    void tearDown() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    void twoFirstRequestsOfOneAgentMailThePersonOnce() throws Exception {
        AgentConfirmationFirstRequestsContract.twoFirstRequestsMailThePersonOnce(store);
    }

    @Test
    void manyAgentsMailThePersonOncePerAgent() throws Exception {
        AgentConfirmationFirstRequestsContract.manyAgentsMailThePersonOncePerAgent(store, 25, 4);
    }

    @Test
    void bothStoresTellWhetherAnotherConfirmationWaitedWhenOneIsSaved() {
        assertSaveTellsWhetherAnotherWaited(store);
        assertSaveTellsWhetherAnotherWaited(new InMemoryAgentConfirmationStore());
    }

    private static void assertSaveTellsWhetherAnotherWaited(AgentConfirmationStore store) {
        String where = store.getClass().getSimpleName();
        // The first confirmation of an agent finds it alone, the next one finds the first waiting.
        assertThat(store.saveNotingWaiting(pending("c-1", "alice", "hash-1", NOW), NOW)).as(where).isFalse();
        assertThat(store.saveNotingWaiting(pending("c-2", "alice", "hash-2", NOW.plusSeconds(1)), NOW.plusSeconds(1)))
                .as(where).isTrue();
        assertThat(store.find("c-2")).as(where).isPresent();
        // Another agent's person is a subject of its own.
        assertThat(store.saveNotingWaiting(pending("c-3", "bob", "hash-1", NOW.plusSeconds(2)), NOW.plusSeconds(2)))
                .as(where).isFalse();

        // A confirmation past its time waits no more.
        assertThat(store.saveNotingWaiting(pending("c-4", "alice", "hash-4", NOW.plusSeconds(1000)),
                NOW.plusSeconds(1000))).as(where).isFalse();

        // A decided confirmation waits no more either.
        AgentConfirmation bobs = store.find("c-3").orElseThrow();
        assertThat(store.transition(bobs.decided(AgentConfirmation.Status.REJECTED, NOW.plusSeconds(10), "bob", null,
                null, bobs.expiresAt()), AgentConfirmation.Status.PENDING)).as(where).isTrue();
        assertThat(store.saveNotingWaiting(pending("c-5", "bob", "hash-2", NOW.plusSeconds(11)), NOW.plusSeconds(11)))
                .as(where).isFalse();
    }

    private static AgentConfirmation pending(String id, String user, String hash, Instant at) {
        return new AgentConfirmation(id, null, "DELEGATED_AGENT", user, "report-agent", "DLG-" + user, user, hash,
                "POST", "/api/exports?format=zip", AgentConfirmation.DECISION_CHALLENGE, "Export outside the delegation",
                "req-" + id, AgentConfirmation.Status.PENDING, at, at.plusSeconds(900), null, null, null, null, null);
    }

    /** The table and its indexes exactly as the canonical schema creates them. */
    private static List<String> agentConfirmationDdl() throws Exception {
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        Matcher table = Pattern.compile("(?is)create table if not exists ctxa_agent_confirmation\\s*\\(.*?\\n\\);")
                .matcher(schema);
        assertThat(table.find()).isTrue();
        Matcher indexes = Pattern.compile("(?is)create index if not exists \\S+\\s+on ctxa_agent_confirmation\\s*\\([^;]*;")
                .matcher(schema);
        List<String> statements = new ArrayList<>();
        statements.add(table.group().replace(";", ""));
        while (indexes.find()) {
            statements.add(indexes.group().replace(";", ""));
        }
        assertThat(statements).hasSize(4);
        return statements;
    }
}
