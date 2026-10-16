package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W7-14: the behaviour difference of the version comparison on PostgreSQL: the sealed decisions of a period per bundle
 * version, stage (the applied decision or a shadow run) and action, with the verdicts of their latest inspection; the
 * bundles not asked for and the packages outside the period are not counted.
 */
class JdbcPromptInspectionBundleOutcomesTest {

    private static final Instant T0 = Instant.parse("2026-10-16T01:00:00Z");
    private static final Instant FROM = Instant.parse("2026-10-16T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-10-17T00:00:00Z");
    private static final String V19 = "2026.10.16-v19.18";
    private static final String V20 = "2026.10.16-v20.23";

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;
    private JdbcPromptInspectionQueries queries;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        Set<String> statements = new LinkedHashSet<>(InspectionSchema.statements());
        statements.addAll(InspectionSchema.sealedShadowStatements());
        for (String statement : statements) {
            jdbc.execute(statement);
        }
        queries = new JdbcPromptInspectionQueries(jdbc);

        seal("p1", T0, V19, null, "ALLOW");
        seal("p2", T0.plusSeconds(60), V19, null, "ALLOW");
        seal("p3", T0.plusSeconds(120), V19, null, "BLOCK");
        seal("p4", T0.plusSeconds(130), V20, "SHADOW", "CHALLENGE");
        seal("p5", T0.plusSeconds(140), "2026.10.16-v20.22", null, "ALLOW");
        seal("outside", Instant.parse("2026-10-20T00:00:00Z"), V19, null, "ALLOW");
        // A package is inspected again under a newer inspector version (the stored results are unique per version).
        result("p1", "prompt-inspector/1", "PASS", T0.plusSeconds(10));
        result("p1", "prompt-inspector/2", "FAIL", T0.plusSeconds(20));
    }

    @AfterEach
    void tearDown() {
        database.close();
    }

    @Test
    void theDecisionsOfThePeriodAreCountedPerBundleStageAndActionWithTheirLatestVerdict() {
        List<JdbcPromptInspectionQueries.BundleOutcome> outcomes = queries.bundleOutcomes(FROM, TO, List.of(V19, V20));

        assertThat(outcomes).containsExactly(
                new JdbcPromptInspectionQueries.BundleOutcome(V19, JdbcPromptInspectionQueries.DECISION_STAGE, "ALLOW",
                        2, 1, 0, 1),
                new JdbcPromptInspectionQueries.BundleOutcome(V19, JdbcPromptInspectionQueries.DECISION_STAGE, "BLOCK",
                        1, 0, 0, 1),
                new JdbcPromptInspectionQueries.BundleOutcome(V20, JdbcPromptInspectionQueries.SHADOW_STAGE,
                        "CHALLENGE", 1, 0, 0, 1));
    }

    @Test
    void noBundleAskedForCountsNothing() {
        assertThat(queries.bundleOutcomes(FROM, TO, List.of())).isEmpty();
        assertThat(queries.bundleOutcomes(FROM, TO, List.of("2026.01.01-v1"))).isEmpty();
    }

    private void seal(String packageId, Instant capturedAt, String bundleVersion, String stage, String action) {
        String decision = "{\"action\":\"" + action + "\""
                + (stage == null ? "" : ",\"decisionAppliedStage\":\"" + stage + "\"") + "}";
        jdbc.update("""
                        insert into sealed_evidence_package (package_id, correlation_id, captured_at,
                               prompt_execution_metadata_json, decision_json, package_hash)
                        values (?, ?, ?, ?, ?, ?)
                        """, packageId, "correlation-" + packageId, Timestamp.from(capturedAt),
                "{\"governanceDescriptor\":{\"promptBundleVersion\":\"" + bundleVersion + "\"}}", decision, "hash");
    }

    private void result(String packageId, String version, String verdict, Instant inspectedAt) {
        jdbc.update("""
                insert into prompt_inspection_result (package_id, inspector_version, dictionary_version, layout_version,
                       verdict, checked_count, mismatch_count, unverifiable_count, check_counts_json, inspection_trigger,
                       inspected_at)
                values (?, ?, 'dictionary-v20', 'v20-dictionary-blocks', ?, 4, 0, 0, '[]', 'AUTO', ?)
                """, packageId, version, verdict, Timestamp.from(inspectedAt));
    }
}
