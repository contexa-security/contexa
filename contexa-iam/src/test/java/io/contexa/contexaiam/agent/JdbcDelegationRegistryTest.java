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
import io.contexa.contexacore.autonomous.agent.RegistryDelegationRecordLookup;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecord;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecordQuery;
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
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** docs/agent OC-1: the delegations kept in the Contexa database follow the shared rules. */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class JdbcDelegationRegistryTest {

    private static final Instant NOW = Instant.parse("2026-10-23T05:00:00Z");
    private static final String SCHEMA = "agent_delegation_test";

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;
    private JdbcDelegationRegistry registry;

    @BeforeEach
    void setUp() throws Exception {
        Connection connection = DriverManager.getConnection(System.getenv("CONTEXA_TEST_DB_URL"),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
        dataSource = new SingleConnectionDataSource(connection, true);
        jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
        jdbc.execute("create schema " + SCHEMA);
        jdbc.execute("set search_path to " + SCHEMA);
        for (String statement : delegationDdl()) {
            jdbc.execute(statement);
        }
        registry = new JdbcDelegationRegistry(jdbc, Duration.ofDays(30), Clock.fixed(NOW, ZoneOffset.UTC));
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
    void aDelegationIsStoredAndReadBackWithEveryFact() {
        AgentDelegation recorded = registry.record(new AgentDelegationRequest("t-1", "alice", "agent-7", "OBJ-1",
                "REPORTING", "Prepare the weekly HX-310 drawing report", List.of("read", "export"),
                List.of("HX-310", "/api/projects/HX-310/**"), true, false, null, NOW.minusSeconds(3600),
                NOW.plus(Duration.ofDays(7)), null, null));

        AgentDelegation read = registry.find(recorded.delegationId()).orElseThrow();

        assertThat(read).isEqualTo(recorded);
        assertThat(read.tenantId()).isEqualTo("t-1");
        assertThat(read.allowedOperations()).containsExactly("READ", "EXPORT");
        assertThat(read.allowedResources()).containsExactly("HX-310", "/api/projects/HX-310/**");
        assertThat(read.privilegedExportAllowed()).isFalse();
        assertThat(read.containmentOnly()).isNull();
        assertThatThrownBy(() -> registry.record(new AgentDelegationRequest(null, "alice", "agent-7", null, null, null,
                null, null, null, null, null, NOW, NOW.plus(Duration.ofDays(31)), null, null)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** RL-6: the quantity limits are stored with the delegation and read back; a delegation that states none reads none. */
    @Test
    void theQuantityLimitsAreStoredAndReadBack() {
        AgentDelegation limited = registry.record(new AgentDelegationRequest(null, "alice", "agent-7", null,
                "REPORTING", null, List.of("READ", "EXPORT"), List.of("HX-310"), null, null, null,
                NOW.minusSeconds(60), NOW.plusSeconds(3600), null, null, 40, 1200));
        AgentDelegation unlimited = registry.record(request(null, "alice", "agent-9", NOW.minusSeconds(60),
                NOW.plusSeconds(3600)));

        AgentDelegation readLimited = registry.find(limited.delegationId()).orElseThrow();
        AgentDelegation readUnlimited = registry.find(unlimited.delegationId()).orElseThrow();

        assertThat(readLimited).isEqualTo(limited);
        assertThat(readLimited.maxItemsPerRequest()).isEqualTo(40);
        assertThat(readLimited.maxItemsTotal()).isEqualTo(1200);
        assertThat(readUnlimited.maxItemsPerRequest()).isNull();
        assertThat(readUnlimited.maxItemsTotal()).isNull();
        // The revocation keeps them.
        AgentDelegation revoked = registry.revoke(limited.delegationId(), "alice", "done").orElseThrow();
        assertThat(revoked.maxItemsPerRequest()).isEqualTo(40);
        assertThat(registry.find(limited.delegationId()).orElseThrow().maxItemsTotal()).isEqualTo(1200);
    }

    @Test
    void theLookupReadsTheHoldingDelegationThenTheLatestAndTheTenantFallback() {
        RegistryDelegationRecordLookup lookup = new RegistryDelegationRecordLookup(registry,
                Clock.fixed(NOW, ZoneOffset.UTC));
        registry.record(request(null, "alice", "agent-7", NOW.minus(Duration.ofDays(3)), NOW.minus(Duration.ofDays(2))));
        AgentDelegation holding = registry.record(request(null, "alice", "agent-7", NOW.minusSeconds(60),
                NOW.plusSeconds(3600)));
        AgentDelegation later = registry.record(request(null, "alice", "agent-7", NOW.plus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(2))));

        assertThat(lookup.find(query("t-1", null, NOW)).map(DelegationRecord::delegationId))
                .contains(holding.delegationId());
        assertThat(lookup.find(query(null, null, NOW.plus(Duration.ofDays(5)))).map(DelegationRecord::delegationId))
                .contains(later.delegationId());
        assertThat(registry.list(null, "alice", "agent-7", 10)).hasSize(3)
                .first().extracting(AgentDelegation::delegationId).isEqualTo(later.delegationId());
        assertThat(registry.list("t-9", null, null, 10)).isEmpty();
    }

    @Test
    void aRevocationIsKeptOnceAndEndsTheDelegation() {
        AgentDelegation delegation = registry.record(request(null, "alice", "agent-7", NOW.minusSeconds(60),
                NOW.plusSeconds(3600)));

        AgentDelegation revoked = registry.revoke(delegation.delegationId(), "admin-1", "hijacked").orElseThrow();
        AgentDelegation again = registry.revoke(delegation.delegationId(), "alice", "again").orElseThrow();

        assertThat(revoked.revokedAt()).isEqualTo(NOW);
        assertThat(revoked.revokedBy()).isEqualTo("admin-1");
        assertThat(again.revokedBy()).isEqualTo("admin-1");
        assertThat(again.revokeReason()).isEqualTo("hijacked");
        assertThat(registry.current(null, "alice", "agent-7", NOW).orElseThrow().validAt(NOW)).isFalse();
        assertThat(registry.revoke("unknown", "admin-1", null)).isEmpty();
    }

    @Test
    void aDeletedAccountsDelegationsAreRemovedInEveryTenant() {
        registry.record(request(null, "alice", "agent-7", NOW, NOW.plusSeconds(3600)));
        registry.record(request("t-1", "alice", "agent-9", NOW, NOW.plusSeconds(3600)));
        AgentDelegation bobs = registry.record(request(null, "bob", "agent-7", NOW, NOW.plusSeconds(3600)));

        assertThat(registry.deleteByDelegator("alice")).isEqualTo(2);

        assertThat(registry.list(null, null, null, 10)).containsExactly(bobs);
    }

    private static AgentDelegationRequest request(String tenant, String delegator, String agent, Instant from,
                                                  Instant until) {
        return new AgentDelegationRequest(tenant, delegator, agent, null, "REPORTING", null, List.of("READ"),
                List.of("HX-310"), null, null, null, from, until, null, null);
    }

    private static DelegationRecordQuery query(String tenant, String delegationId, Instant at) {
        return new DelegationRecordQuery(tenant, "alice", "agent-7", delegationId, null, at);
    }

    private static List<String> delegationDdl() throws Exception {
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        Matcher table = Pattern.compile("(?is)create table if not exists ctxa_agent_delegation_record\\s*\\(.*?\\n\\);")
                .matcher(schema);
        assertThat(table.find()).isTrue();
        Matcher indexes = Pattern.compile("(?is)create (?:unique )?index if not exists \\S+\\s+on ctxa_agent_delegation_record[^;]*;")
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
