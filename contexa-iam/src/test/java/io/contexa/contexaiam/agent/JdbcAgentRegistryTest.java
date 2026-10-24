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

import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationSource;
import io.contexa.contexacore.autonomous.agent.AgentSighting;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A1-6: the database registry keeps the same facts as the in-memory one. It runs only against the isolated database
 * named by {@code CONTEXA_TEST_DB_URL}, in a schema of its own that it drops afterwards.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class JdbcAgentRegistryTest {

    private static final Instant NOW = Instant.parse("2026-10-22T05:00:00Z");
    private static final String SCHEMA = "agent_registry_test";

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;
    private JdbcAgentRegistry registry;

    @BeforeEach
    void setUp() throws Exception {
        Connection connection = DriverManager.getConnection(System.getenv("CONTEXA_TEST_DB_URL"),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
        dataSource = new SingleConnectionDataSource(connection, true);
        jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
        jdbc.execute("create schema " + SCHEMA);
        jdbc.execute("set search_path to " + SCHEMA);
        for (String statement : agentRegistrationDdl()) {
            jdbc.execute(statement);
        }
        registry = new JdbcAgentRegistry(jdbc, Clock.fixed(NOW, ZoneOffset.UTC));
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
    void sightingsRegisterAnObservedAgentAndMoveOnlyItsLastSeenTimeForward() {
        registry.observe(new AgentSighting("tenant-acme", "agent-7", "DELEGATED_AGENT", null,
                Instant.parse("2026-10-22T04:00:00Z")));
        registry.observe(new AgentSighting("tenant-acme", "agent-7", "AUTONOMOUS_AGENT", "agent-client",
                Instant.parse("2026-10-22T04:30:00Z")));
        AgentRegistration latest = registry.observe(new AgentSighting("tenant-acme", "agent-7", "DELEGATED_AGENT",
                null, Instant.parse("2026-10-22T04:10:00Z")));

        assertThat(latest.source()).isEqualTo(AgentRegistrationSource.OBSERVED);
        assertThat(latest.status()).isEqualTo(AgentStatus.ACTIVE);
        assertThat(latest.allowlisted()).isFalse();
        assertThat(latest.firstSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:00:00Z"));
        assertThat(latest.lastSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:30:00Z"));
        assertThat(latest.lastSubjectKind()).isEqualTo("AUTONOMOUS_AGENT");
        assertThat(latest.clientId()).isEqualTo("agent-client");
    }

    @Test
    void aClientMatchesTheAgentItsTokensAreIssuedToAndALifeCycleChangeShowsAtOnce() {
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));
        registry.register(new AgentRegistrationRequest(null, "worker", "Named like a client", null, null, "dave", null));
        registry.register(new AgentRegistrationRequest(null, "worker-agent", "Issued to worker", null, "worker", "dave", null));
        registry.register(new AgentRegistrationRequest("tenant-acme", "acme-bot", "Acme", null, "acme-client", "erin", null));

        assertThat(registry.findByClientId(null, "report-client")).map(AgentRegistration::agentId).contains("report-bot");
        assertThat(registry.findByClientId(null, "worker")).map(AgentRegistration::agentId).contains("worker-agent");
        assertThat(registry.findByClientId(null, "acme-client")).isEmpty();
        assertThat(registry.findByClientId("tenant-acme", "acme-client")).map(AgentRegistration::agentId).contains("acme-bot");

        registry.deregister(null, "report-bot", "retired");

        assertThat(registry.findByClientId(null, "report-client")).map(AgentRegistration::status)
                .contains(AgentStatus.DEREGISTERED);
    }

    @Test
    void lifeCycleChangesFollowTheSharedRules() {
        registry.observe(new AgentSighting(null, "agent-7", "DELEGATED_AGENT", null, Instant.parse("2026-10-22T04:00:00Z")));

        AgentRegistration registered = registry.register(new AgentRegistrationRequest(
                null, "agent-7", "Report assistant", "report-blueprint", null, "carol", null));
        AgentRegistration transferred = registry.transferSponsor(null, "agent-7", "dave").orElseThrow();
        AgentRegistration deregistered = registry.deregister(null, "agent-7", "offboarded").orElseThrow();
        AgentRegistration restored = registry.register(new AgentRegistrationRequest(
                null, "agent-7", null, null, null, null, null));

        assertThat(registered.source()).isEqualTo(AgentRegistrationSource.LIFECYCLE);
        assertThat(registered.allowlisted()).isTrue();
        assertThat(registered.registeredAt()).isEqualTo(NOW);
        assertThat(registered.firstSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:00:00Z"));
        assertThat(transferred.sponsorId()).isEqualTo("dave");
        assertThat(deregistered.status()).isEqualTo(AgentStatus.DEREGISTERED);
        assertThat(deregistered.statusReason()).isEqualTo("offboarded");
        assertThat(restored.status()).isEqualTo(AgentStatus.ACTIVE);
        assertThat(restored.sponsorId()).isEqualTo("dave");
        assertThat(restored.displayName()).isEqualTo("Report assistant");
        assertThat(registry.find(null, "agent-7")).contains(restored);
        assertThat(registry.deregister(null, "unknown-agent", "gone")).isEmpty();
    }

    @Test
    void tenantsAreKeptApartAndTheListShowsTheLatestSeenFirst() {
        registry.observe(new AgentSighting("tenant-a", "agent-1", "DELEGATED_AGENT", null, Instant.parse("2026-10-22T01:00:00Z")));
        registry.observe(new AgentSighting("tenant-a", "agent-2", "DELEGATED_AGENT", null, Instant.parse("2026-10-22T03:00:00Z")));
        registry.observe(new AgentSighting("tenant-b", "agent-1", "AUTONOMOUS_AGENT", null, Instant.parse("2026-10-22T02:00:00Z")));

        assertThat(registry.find("tenant-b", "agent-1").orElseThrow().lastSubjectKind()).isEqualTo("AUTONOMOUS_AGENT");
        assertThat(registry.list("tenant-a", 10)).extracting(AgentRegistration::agentId).containsExactly("agent-2", "agent-1");
        assertThat(registry.list(null, 2)).extracting(AgentRegistration::tenantId).containsExactly("tenant-a", "tenant-b");
    }

    @Test
    void concurrentSightingsOfANewAgentMakeOneRow() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(4);
        JdbcTemplate shared = new JdbcTemplate(new SingleConnectionDataSource(DriverManager.getConnection(
                System.getenv("CONTEXA_TEST_DB_URL"), System.getenv("CONTEXA_TEST_DB_USERNAME"),
                System.getenv("CONTEXA_TEST_DB_PASSWORD")), true));
        shared.execute("set search_path to " + SCHEMA);
        JdbcAgentRegistry concurrent = new JdbcAgentRegistry(shared, Clock.fixed(NOW, ZoneOffset.UTC));
        try {
            List<Future<AgentRegistration>> sightings = List.of(
                    pool.submit(() -> concurrent.observe(new AgentSighting(null, "agent-7", "DELEGATED_AGENT", null,
                            Instant.parse("2026-10-22T04:00:00Z")))),
                    pool.submit(() -> concurrent.observe(new AgentSighting(null, "agent-7", "DELEGATED_AGENT", null,
                            Instant.parse("2026-10-22T04:01:00Z")))),
                    pool.submit(() -> concurrent.observe(new AgentSighting(null, "agent-7", "DELEGATED_AGENT", null,
                            Instant.parse("2026-10-22T04:02:00Z")))));
            for (Future<AgentRegistration> sighting : sightings) {
                sighting.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(jdbc.queryForObject("select count(*) from agent_registration", Integer.class)).isEqualTo(1);
        AgentRegistration agent = registry.find(null, "agent-7").orElseThrow();
        assertThat(agent.firstSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:00:00Z"));
        assertThat(agent.lastSeenAt()).isEqualTo(Instant.parse("2026-10-22T04:02:00Z"));
    }

    /**
     * docs/agent A5-3: a suspension keeps its reason and shows on the agent's client at once; a resumption ends only a
     * suspension, a deregistered agent is not suspended, and an unknown agent is neither.
     */
    @Test
    void aSuspensionKeepsItsReasonAndOnlyAResumptionEndsIt() {
        registry.register(new AgentRegistrationRequest("tenant-acme", "agent-7", "Report", null, "agent-client",
                "carol", true));
        registry.register(new AgentRegistrationRequest("tenant-acme", "agent-8", "Gone", null, "gone-client",
                "carol", true));
        registry.deregister("tenant-acme", "agent-8", "retired");

        assertThat(registry.suspend("tenant-acme", "agent-7", "BLOCK: exported every document"))
                .map(AgentRegistration::status).contains(AgentStatus.SUSPENDED);
        assertThat(registry.findByClientId("tenant-acme", "agent-client")).map(AgentRegistration::statusReason)
                .contains("BLOCK: exported every document");
        // A provider's re-registration does not lift a security decision.
        registry.register(new AgentRegistrationRequest("tenant-acme", "agent-7", "Report", null, "agent-client",
                "carol", true));
        assertThat(registry.find("tenant-acme", "agent-7")).map(AgentRegistration::status)
                .contains(AgentStatus.SUSPENDED);

        assertThat(registry.resume("tenant-acme", "agent-7", "RELEASED: reviewed")).map(AgentRegistration::status)
                .contains(AgentStatus.ACTIVE);
        assertThat(registry.find("tenant-acme", "agent-7")).map(AgentRegistration::statusReason)
                .contains("RELEASED: reviewed");
        assertThat(registry.resume("tenant-acme", "agent-7", "again")).map(AgentRegistration::statusReason)
                .contains("RELEASED: reviewed");
        assertThat(registry.suspend("tenant-acme", "agent-8", "BLOCK: late")).map(AgentRegistration::status)
                .contains(AgentStatus.DEREGISTERED);
        assertThat(registry.suspend("tenant-acme", "agent-9", "BLOCK: unknown")).isEmpty();
        assertThat(registry.resume("tenant-other", "agent-7", "wrong tenant")).isEmpty();
    }

    /** The table and its indexes exactly as the canonical schema creates them. */
    /** docs/agent OC-3: removal takes the agent and its history away; another agent and tenant stay. */
    @Test
    void aRemovedAgentIsGoneWithItsHistory() {
        registry.register(new AgentRegistrationRequest("tenant-acme", "agent-7", "Report", null, "agent-client",
                "carol", true));
        registry.register(new AgentRegistrationRequest("tenant-acme", "agent-8", "Other", null, "other-client",
                "carol", true));

        assertThat(registry.remove("tenant-acme", "agent-7")).isPresent();

        assertThat(registry.find("tenant-acme", "agent-7")).isEmpty();
        assertThat(registry.findByClientId("tenant-acme", "agent-client")).isEmpty();
        assertThat(registry.find("tenant-acme", "agent-8")).isPresent();
        assertThat(registry.remove("tenant-acme", "agent-7")).isEmpty();
    }

    private static List<String> agentRegistrationDdl() throws Exception {
        String schema = new ClassPathResource("db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        Matcher table = Pattern.compile("(?is)create table if not exists agent_registration\\s*\\(.*?\\n\\);").matcher(schema);
        assertThat(table.find()).isTrue();
        Matcher indexes = Pattern.compile("(?is)create (?:unique )?index if not exists \\S+\\s+on agent_registration[^;]*;")
                .matcher(schema);
        List<String> statements = new ArrayList<>();
        statements.add(table.group().replace(";", ""));
        while (indexes.find()) {
            statements.add(indexes.group().replace(";", ""));
        }
        assertThat(statements).hasSizeGreaterThan(1);
        return statements;
    }
}
