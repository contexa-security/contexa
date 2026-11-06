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

import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationAuthorizer;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentConfirmationStore;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * docs/agent A5-2: the confirmations are kept in the Contexa database as the in-memory store keeps them, and a
 * decision or the use of an approval is made once. It runs only against the isolated database named by
 * {@code CONTEXA_TEST_DB_URL}, in a schema of its own that it drops afterwards.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class JdbcAgentConfirmationStoreTest {

    private static final Instant NOW = Instant.parse("2026-10-24T02:00:00.123456Z");
    private static final String SCHEMA = "agent_confirmation_test";

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
        for (String statement : agentConfirmationDdl()) {
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
    void theDatabaseKeepsTheConfirmationsAsTheInMemoryStoreDoes() {
        assertKeepsConfirmations(new JdbcAgentConfirmationStore(jdbc));
        assertKeepsConfirmations(new InMemoryAgentConfirmationStore());
    }

    /** A value past what a column holds is kept the same by both stores, so a person reads the same in either. */
    @Test
    void bothStoresKeepAValuePastItsColumnTheSameWay() {
        AgentConfirmation oversized = new AgentConfirmation("c-big", null, "DELEGATED_AGENT", "alice", "report-agent",
                null, "alice", "hash-1", "M".repeat(20), "/" + "a".repeat(3000), AgentConfirmation.REQUESTED, null,
                "r".repeat(200), AgentConfirmation.Status.PENDING, NOW, NOW.plusSeconds(900), null, null, null, null,
                null);
        AgentConfirmationStore database = new JdbcAgentConfirmationStore(jdbc);
        AgentConfirmationStore memory = new InMemoryAgentConfirmationStore();

        AgentConfirmation savedThere = database.save(oversized);
        AgentConfirmation savedHere = memory.save(oversized);

        assertThat(savedThere).isEqualTo(savedHere);
        assertThat(database.find("c-big")).isEqualTo(memory.find("c-big"));
        assertThat(memory.find("c-big")).hasValueSatisfying(kept -> {
            assertThat(kept.method()).hasSize(16);
            assertThat(kept.target()).hasSize(2048);
            assertThat(kept.correlationId()).hasSize(160);
        });
    }

    /** The size of the request's body is kept alike, and so is a size never recorded; the body itself is not kept. */
    @Test
    void bothStoresKeepTheSizeOfTheRequestsBody() {
        for (AgentConfirmationStore store : List.of(new JdbcAgentConfirmationStore(jdbc),
                new InMemoryAgentConfirmationStore())) {
            store.save(sized("c-body", 1234L));
            store.save(sized("c-none", 0L));
            store.save(sized("c-unseen", AgentConfirmation.BODY_NOT_SEEN));
            store.save(sized("c-old", null));

            assertThat(store.find("c-body")).map(AgentConfirmation::bodyBytes).as(store.getClass().getSimpleName())
                    .contains(1234L);
            assertThat(store.find("c-none")).map(AgentConfirmation::bodyBytes).contains(0L);
            assertThat(store.find("c-unseen")).map(AgentConfirmation::bodyBytes)
                    .contains(AgentConfirmation.BODY_NOT_SEEN);
            assertThat(store.find("c-old")).hasValueSatisfying(old -> assertThat(old.bodyBytes()).isNull());
            // A decision keeps it.
            AgentConfirmation approved = store.find("c-body").orElseThrow().decided(AgentConfirmation.Status.APPROVED,
                    NOW.plusSeconds(5), "alice", null, "ctxa-sig:k1:abc", NOW.plusSeconds(905));
            store.transition(approved, AgentConfirmation.Status.PENDING);
            assertThat(store.find("c-body")).map(AgentConfirmation::bodyBytes).contains(1234L);
        }
    }

    private static AgentConfirmation sized(String id, Long bodyBytes) {
        return new AgentConfirmation(id, null, "DELEGATED_AGENT", "alice", "report-agent", null, "alice", "hash-" + id,
                "POST", "/api/exports", AgentConfirmation.DECISION_CHALLENGE, null, null,
                AgentConfirmation.Status.PENDING, NOW, NOW.plusSeconds(900), null, null, null, null, null, bodyBytes);
    }

    /**
     * An identifier past its column is never cut, since a cut one names another delegation, agent or person: neither
     * store gets the confirmation, and the request it was asked for is refused alike.
     */
    @Test
    void neitherStoreTakesAConfirmationWhoseIdentifiersItCannotKeep() {
        List<ZeroTrustSubject> unkeepable = List.of(
                new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT, "report-agent", "d".repeat(65)),
                new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT, "a".repeat(256), null),
                new ZeroTrustSubject("t".repeat(256), "alice", SubjectKind.DELEGATED_AGENT, "report-agent", null));

        for (AgentConfirmationStore store : List.of(new JdbcAgentConfirmationStore(jdbc),
                new InMemoryAgentConfirmationStore())) {
            AgentConfirmationService service = new AgentConfirmationService(store,
                    mock(AgentConfirmationAuthorizer.class), null, null, null, Duration.ofMinutes(15), null);
            for (ZeroTrustSubject subject : unkeepable) {
                assertThat(service.request(new AgentConfirmationService.ConfirmationRequest(subject, "hash-1", "POST",
                        "/api/exports", AgentConfirmation.DECISION_CHALLENGE, null, "req-1", null)))
                        .as("%s, %s", store.getClass().getSimpleName(), subject).isEmpty();
            }
            assertThat(store.list(null, 10)).isEmpty();
        }
    }

    private static void assertKeepsConfirmations(AgentConfirmationStore store) {
        AgentConfirmation first = store.save(pending("c-1", "alice", "hash-1", NOW));
        store.save(pending("c-2", "alice", "hash-1", NOW.plusSeconds(1)));
        store.save(pending("c-3", "bob", "hash-1", NOW.plusSeconds(2)));

        assertThat(store.find("c-1")).contains(first);
        assertThat(store.latest("alice::agent::report-agent", "hash-1", AgentConfirmation.Status.PENDING))
                .map(AgentConfirmation::confirmationId).contains("c-2");
        // Whether a confirmation of the agent waits, of any request: pending and in its time.
        assertThat(store.waiting("alice::agent::report-agent", NOW.plusSeconds(10))).isTrue();
        assertThat(store.waiting("carol::agent::report-agent", NOW.plusSeconds(10))).isFalse();
        assertThat(store.waiting("alice::agent::report-agent", NOW.plusSeconds(902))).isFalse();
        assertThat(store.latest("alice::agent::report-agent", "hash-2", AgentConfirmation.Status.PENDING)).isEmpty();
        assertThat(store.forRecipient("alice", 10)).extracting(AgentConfirmation::confirmationId)
                .containsExactly("c-2", "c-1");
        assertThat(store.list(null, 10)).hasSize(3);
        assertThat(store.list("tenant-acme", 10)).isEmpty();

        AgentConfirmation approved = first.decided(AgentConfirmation.Status.APPROVED, NOW.plusSeconds(30), "alice",
                "fine", "ctxa-sig:k1:abc", NOW.plusSeconds(930));
        assertThat(store.transition(approved, AgentConfirmation.Status.PENDING)).isTrue();
        // A second decision of the same confirmation does not replace the first.
        assertThat(store.transition(first.decided(AgentConfirmation.Status.REJECTED, NOW.plusSeconds(31), "alice",
                null, null, first.expiresAt()), AgentConfirmation.Status.PENDING)).isFalse();
        assertThat(store.find("c-1")).contains(approved);
        assertThat(store.latest("alice::agent::report-agent", "hash-1", AgentConfirmation.Status.APPROVED))
                .map(AgentConfirmation::confirmationId).contains("c-1");

        assertThat(store.markUsed("c-1", "hash-2", NOW.plusSeconds(40))).isFalse();
        assertThat(store.markUsed("c-1", "hash-1", NOW.plusSeconds(40))).isTrue();
        assertThat(store.markUsed("c-1", "hash-1", NOW.plusSeconds(41))).isFalse();
        assertThat(store.find("c-1")).hasValueSatisfying(used -> {
            assertThat(used.status()).isEqualTo(AgentConfirmation.Status.USED);
            assertThat(used.usedAt()).isEqualTo(NOW.plusSeconds(40));
            assertThat(used.authorizationId()).isEqualTo("ctxa-sig:k1:abc");
        });

        // A decided confirmation waits no more; the other one of the agent still does.
        assertThat(store.waiting("alice::agent::report-agent", NOW.plusSeconds(10))).isTrue();
        store.transition(store.find("c-2").orElseThrow().decided(AgentConfirmation.Status.REJECTED, NOW.plusSeconds(50),
                "alice", null, null, NOW.plusSeconds(901)), AgentConfirmation.Status.PENDING);
        assertThat(store.waiting("alice::agent::report-agent", NOW.plusSeconds(60))).isFalse();
        assertThat(store.waiting("bob::agent::report-agent", NOW.plusSeconds(60))).isTrue();

        assertThat(store.overdue(NOW.plusSeconds(902), 10)).extracting(AgentConfirmation::confirmationId)
                .containsExactly("c-3");
        assertThat(store.overdue(NOW.plusSeconds(10), 10)).isEmpty();
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
