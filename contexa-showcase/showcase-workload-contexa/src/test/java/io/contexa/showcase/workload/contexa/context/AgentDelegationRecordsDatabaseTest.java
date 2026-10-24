package io.contexa.showcase.workload.contexa.context;

import io.contexa.contexacore.autonomous.context.enricher.DelegationRecord;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecordQuery;
import io.contexa.showcase.business.context.AgentDelegations;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.business.run.RunRegistry;
import io.contexa.showcase.business.work.WorkDatabase;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * docs/agent A7-0: a run's delegation of record is written to the business database, read by the engine's delegation
 * record lookup for the run's principal and agent, and removed with the run. Runs on an isolated PostgreSQL named by
 * CONTEXA_TEST_DB_URL (never the showcase's own database), in a schema of its own that is dropped afterwards.
 */
class AgentDelegationRecordsDatabaseTest {

    private static final String SCHEMA = "a70_work_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    private static DriverManagerDataSource dataSource;
    private static WorkDatabase database;

    @BeforeAll
    static void migrate() {
        String url = System.getenv("CONTEXA_TEST_DB_URL");
        assumeTrue(url != null && !url.isBlank(), "CONTEXA_TEST_DB_URL names no isolated test database");
        String user = System.getenv("CONTEXA_TEST_DB_USERNAME");
        String password = System.getenv("CONTEXA_TEST_DB_PASSWORD");
        Flyway.configure().dataSource(url, user, password).schemas(SCHEMA).createSchemas(true)
                .locations("classpath:db/migration/work").load().migrate();
        dataSource = new DriverManagerDataSource(url + (url.contains("?") ? "&" : "?") + "currentSchema=" + SCHEMA,
                user, password);
        database = new WorkDatabase(dataSource, null);
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.update("insert into role (role_key, display_name_en, display_name_ko) values ('ENGINEER', 'Engineer', '엔지니어')");
        jdbc.update("insert into employee (employee_key, role_key, display_name, department) "
                + "values ('eng-k', 'ENGINEER', 'Engineer K', 'Design')");
    }

    @AfterAll
    static void drop() {
        if (dataSource != null) {
            new JdbcTemplate(dataSource).execute("drop schema " + SCHEMA + " cascade");
        }
    }

    @Test
    void aRunsDelegationReachesTheEngineForTheRunsPrincipalAndAgentAndGoesWithTheRun() {
        RunRegistry runs = new RunRegistry(database);
        runs.registerPrincipal("v1a2b3c-eng-k", "run-1a2b3c", "eng-k", "org-1", "tenant-1");
        Instant from = Instant.parse("2026-09-30T13:00:00Z");
        Instant until = Instant.parse("2026-09-30T17:00:00Z");
        runs.addFacts("run-1a2b3c", new RunFacts(List.of(), List.of(), List.of(), List.of(), List.of(), List.of(
                new RunFacts.Delegation("DLG-1a2b3c-1", "eng-k", "agt-1a2b3c-report", "DLG-1a2b3c-1", "REPORTING",
                        "Prepare the weekly HX-310 drawing report", List.of("DOCUMENT_READ", "EXPORT"),
                        List.of("HX-310"), false, from, until, false, "eng-k", from.minusSeconds(300)))));
        ShowcaseDelegationRecordLookup lookup = new ShowcaseDelegationRecordLookup(new AgentDelegations(database));

        DelegationRecord found = lookup.find(new DelegationRecordQuery("tenant-1", "v1a2b3c-eng-k",
                "agt-1a2b3c-report", null, null, from.plusSeconds(600))).orElseThrow();

        assertThat(found.delegationId()).isEqualTo("DLG-1a2b3c-1");
        assertThat(found.delegatorId()).isEqualTo("v1a2b3c-eng-k");
        assertThat(found.agentId()).isEqualTo("agt-1a2b3c-report");
        assertThat(found.objectiveFamily()).isEqualTo("REPORTING");
        assertThat(found.objectiveSummary()).isEqualTo("Prepare the weekly HX-310 drawing report");
        assertThat(found.allowedOperations()).containsExactly("DOCUMENT_READ", "EXPORT");
        assertThat(found.allowedResources()).containsExactly("HX-310");
        assertThat(found.approvalRequired()).isFalse();
        assertThat(found.expiresAt()).isEqualTo(until);
        // A2-10: the employee who wrote the record is named by the run's principal, with when it was written.
        assertThat(found.recordedBy()).isEqualTo("v1a2b3c-eng-k");
        assertThat(found.recordedAt()).isEqualTo(from.minusSeconds(300));
        assertThat(lookup.find(new DelegationRecordQuery("tenant-1", "v1a2b3c-eng-k", "agt-other", null, null,
                from))).isEmpty();
        assertThat(lookup.find(new DelegationRecordQuery("tenant-1", "someone-else", "agt-1a2b3c-report", null, null,
                from))).isEmpty();

        assertThat(runs.deleteRun("run-1a2b3c")).isGreaterThanOrEqualTo(2);
        assertThat(runs.remainingRows("run-1a2b3c")).isZero();
        assertThat(lookup.find(new DelegationRecordQuery("tenant-1", "v1a2b3c-eng-k", "agt-1a2b3c-report", null,
                null, from))).isEmpty();
    }

    @Test
    void aRevokedDelegationEndsWhenItBegan() {
        RunRegistry runs = new RunRegistry(database);
        runs.registerPrincipal("v4d5e6f-eng-k", "run-4d5e6f", "eng-k", "org-1", "tenant-1");
        Instant from = Instant.parse("2026-09-30T13:00:00Z");
        runs.addFacts("run-4d5e6f", new RunFacts(List.of(), List.of(), List.of(), List.of(), List.of(), List.of(
                new RunFacts.Delegation("DLG-4d5e6f-1", "eng-k", "agt-4d5e6f-report", null, "REPORTING", null,
                        List.of("DOCUMENT_READ"), List.of("HX-310"), true, from, from.plusSeconds(3600), true))));

        DelegationRecord found = new ShowcaseDelegationRecordLookup(new AgentDelegations(database))
                .find(new DelegationRecordQuery(null, "v4d5e6f-eng-k", "agt-4d5e6f-report", "DLG-4d5e6f-1", null,
                        from)).orElseThrow();

        assertThat(found.expiresAt()).isEqualTo(from);
        assertThat(found.approvalRequired()).isTrue();
        // A record that does not say who wrote it or when says neither.
        assertThat(found.recordedBy()).isNull();
        assertThat(found.recordedAt()).isNull();
        runs.deleteRun("run-4d5e6f");
    }
}
