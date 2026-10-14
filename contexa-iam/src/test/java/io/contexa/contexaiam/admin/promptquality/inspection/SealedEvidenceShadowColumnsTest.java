package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R4-S3: the sealed package shadows as the OSS schema declares them. Only the two shadows a query reads (request facts
 * and decision) are filled, and no GIN index is kept, since no query uses a GIN operator. The test sits beside the
 * inspection schema helper, which splits the OSS schema as the installer does.
 */
class SealedEvidenceShadowColumnsTest {

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        for (String statement : InspectionSchema.sealedShadowStatements()) {
            jdbc.execute(statement);
        }
    }

    @AfterEach
    void tearDown() {
        database.close();
    }

    @Test
    void aSealedPackageFillsOnlyTheTwoShadowsAQueryReads() {
        jdbc.update("insert into sealed_evidence_package (package_id, correlation_id, captured_at, package_hash, "
                + "request_facts_json, auth_state_json, canonical_context_json, baseline_snapshot_json, "
                + "rag_results_json, decision_json) values ('p1', 'c1', now(), 'hash', '{\"a\":1}', '{\"a\":2}', "
                + "'{\"a\":3}', '{\"a\":4}', '{\"a\":5}', '{\"action\":\"ALLOW\"}')");

        Map<String, Object> row = jdbc.queryForMap("select request_facts_jsonb is not null as request_facts, "
                + "decision_jsonb is not null as decision, auth_state_jsonb is null as auth_state_empty, "
                + "canonical_context_jsonb is null as canonical_context_empty, "
                + "baseline_snapshot_jsonb is null as baseline_snapshot_empty, "
                + "rag_results_jsonb is null as rag_results_empty from sealed_evidence_package");

        assertThat(row).containsEntry("request_facts", true).containsEntry("decision", true)
                .containsEntry("auth_state_empty", true).containsEntry("canonical_context_empty", true)
                .containsEntry("baseline_snapshot_empty", true).containsEntry("rag_results_empty", true);
    }

    @Test
    void noGinIndexIsKeptOnTheSealedPackages() {
        assertThat(jdbc.queryForList("select indexname from pg_indexes where tablename = 'sealed_evidence_package' "
                + "and indexdef ilike '%using gin%'", String.class)).isEmpty();
    }
}
