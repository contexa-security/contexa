package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
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
 * N-SHD-1 on PostgreSQL: each shadow run of the asked bundles in a period is paired with the sealed decision of the
 * request its copy was made from (the decision's correlation id); a shadow run whose decision was not sealed, or that
 * was sealed before its seal named the request, has no pair, and the shadow runs of other bundles are not listed.
 */
class JdbcPromptInspectionShadowPairsTest {

    private static final Instant T0 = Instant.parse("2026-10-16T01:00:00Z");
    private static final Instant FROM = Instant.parse("2026-10-16T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-10-17T00:00:00Z");
    private static final String V19 = "2026.10.16-v19.19";
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

        seal("d-1", "req-1", T0, V19, "{\"action\":\"BLOCK\",\"decisionAppliedStage\":\"LAYER1\"}");
        seal("s-1", "shadow-a", T0.plusSeconds(5), V20, shadow("ALLOW", "req-1"));
        seal("d-2", "req-2", T0.plusSeconds(60), V19, "{\"action\":\"ALLOW\"}");
        seal("s-2", "shadow-b", T0.plusSeconds(65), V20, shadow("ALLOW", "req-2"));
        seal("s-3", "shadow-c", T0.plusSeconds(120), V20, shadow("CHALLENGE", "req-3"));
        seal("s-4", "shadow-d", T0.plusSeconds(180), V20, "{\"action\":\"BLOCK\",\"decisionAppliedStage\":\"SHADOW\"}");
        seal("s-5", "shadow-e", T0.plusSeconds(190), "2026.10.16-v20.22", shadow("ALLOW", "req-1"));
        seal("s-6", "shadow-f", Instant.parse("2026-10-20T00:00:00Z"), V20, shadow("ALLOW", "req-2"));
    }

    @AfterEach
    void tearDown() {
        database.close();
    }

    @Test
    void eachShadowRunIsPairedWithTheSealedDecisionOfItsRequest() {
        List<JdbcPromptInspectionQueries.ShadowPair> pairs = queries.shadowPairs(FROM, TO, List.of(V19, V20));

        assertThat(pairs).extracting(JdbcPromptInspectionQueries.ShadowPair::shadowPackageId)
                .containsExactly("s-4", "s-3", "s-2", "s-1");
        assertThat(pairs.get(3)).isEqualTo(new JdbcPromptInspectionQueries.ShadowPair("req-1", T0.plusSeconds(5),
                "s-1", V20, "ALLOW", "d-1", V19, "BLOCK"));
        assertThat(pairs.get(2)).isEqualTo(new JdbcPromptInspectionQueries.ShadowPair("req-2", T0.plusSeconds(65),
                "s-2", V20, "ALLOW", "d-2", V19, "ALLOW"));
        // The decision of req-3 was not sealed; s-4 was sealed before a shadow seal named its request.
        assertThat(pairs.get(1).decisionPackageId()).isNull();
        assertThat(pairs.get(1).requestId()).isEqualTo("req-3");
        assertThat(pairs.get(0).requestId()).isNull();
        assertThat(pairs.get(0).decisionPackageId()).isNull();
    }

    @Test
    void noBundleAskedForPairsNothing() {
        assertThat(queries.shadowPairs(FROM, TO, List.of())).isEmpty();
        assertThat(queries.shadowPairs(FROM, TO, List.of(V19))).isEmpty();
    }

    private static String shadow(String action, String originalRequestId) {
        return "{\"action\":\"" + action + "\",\"decisionAppliedStage\":\"SHADOW\",\""
                + PromptShadowRun.ORIGINAL_REQUEST_ID + "\":\"" + originalRequestId + "\"}";
    }

    private void seal(String packageId, String correlationId, Instant capturedAt, String bundleVersion,
                      String decision) {
        jdbc.update("""
                        insert into sealed_evidence_package (package_id, correlation_id, captured_at,
                               prompt_execution_metadata_json, decision_json, package_hash)
                        values (?, ?, ?, ?, ?, ?)
                        """, packageId, correlationId, Timestamp.from(capturedAt),
                "{\"governanceDescriptor\":{\"promptBundleVersion\":\"" + bundleVersion + "\"}}", decision, "hash");
    }
}
