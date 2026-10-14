package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionTrigger;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The inspection read model on PostgreSQL: the sealed packages of a period with their latest result (or none), the
 * filters of the package list and the overview counts.
 */
class JdbcPromptInspectionQueriesTest {

    private static final Instant T0 = Instant.parse("2026-10-11T23:00:00Z");
    private static final Instant FROM = Instant.parse("2026-10-11T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-10-13T00:00:00Z");

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;
    private JdbcPromptInspectionResultStore store;
    private JdbcPromptInspectionQueries queries;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        for (String statement : InspectionSchema.statements()) {
            jdbc.execute(statement);
        }
        store = new JdbcPromptInspectionResultStore(jdbc,
                new TransactionTemplate(new DataSourceTransactionManager(database.dataSource())), new ObjectMapper());
        queries = new JdbcPromptInspectionQueries(jdbc);

        seal("p1", T0, "user-a", "POST", "/api/projects/GB-500/exports", "exportDocuments", "2026.10.11-v19.8");
        seal("p2", T0.plusSeconds(3600), "user-b", "GET", "/api/documents/D-1", "readDocument", "2026.10.11-v19.8");
        seal("p3", T0.plusSeconds(7200), "user-a", "POST", "/api/projects/GB-500/exports", "exportDocuments",
                "2026.10.11-v19.7");
        seal("outside", Instant.parse("2026-10-20T00:00:00Z"), "user-c", "GET", "/x", "x", "2026.10.11-v19.8");
        store.save(result("p1", "prompt-inspector/1", PromptInspectionVerdict.FAIL, List.of(
                mismatch("FACT_ACCURACY", "REQUEST", "Action"), mismatch("FACT_ACCURACY", "REQUEST", "Target"),
                unverifiable("PAST_RECORD_NOTATION", "PAST RECORDS", null))), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(60));
        store.save(result("p3", "prompt-inspector/0", PromptInspectionVerdict.PASS, List.of()),
                PromptInspectionTrigger.AUTO, T0.plusSeconds(7300));
        store.save(result("p3", "prompt-inspector/1", PromptInspectionVerdict.INCOMPLETE, List.of(
                unverifiable("FACT_ACCURACY", "REQUEST", "Time"))), PromptInspectionTrigger.OPERATOR,
                T0.plusSeconds(7400));
    }

    @AfterEach
    void tearDown() {
        database.close();
    }

    @Test
    void thePackagesOfThePeriodAreListedNewestFirstWithTheirLatestResult() {
        JdbcPromptInspectionQueries.PackagePage page = queries.packages(filter(null, null, null, null), 0, 20);

        assertThat(page.total()).isEqualTo(3);
        assertThat(page.rows()).extracting(JdbcPromptInspectionQueries.PackageRow::packageId)
                .containsExactly("p3", "p2", "p1");
        JdbcPromptInspectionQueries.PackageRow p3 = page.rows().get(0);
        assertThat(p3.verdict()).isEqualTo("INCOMPLETE");
        assertThat(p3.inspectorVersion()).isEqualTo("prompt-inspector/1");
        assertThat(p3.unverifiableCount()).isEqualTo(1);
        assertThat(page.rows().get(1).verdict()).isEqualTo(JdbcPromptInspectionQueries.NOT_INSPECTED);
        assertThat(page.rows().get(1).inspectedAt()).isNull();
        JdbcPromptInspectionQueries.PackageRow p1 = page.rows().get(2);
        assertThat(p1.verdict()).isEqualTo("FAIL");
        assertThat(p1.mismatchCount()).isEqualTo(2);
        assertThat(p1.userId()).isEqualTo("user-a");
        assertThat(p1.httpMethod()).isEqualTo("POST");
        assertThat(p1.requestPath()).isEqualTo("/api/projects/GB-500/exports");
        assertThat(p1.resourceId()).isEqualTo("exportDocuments");
        assertThat(p1.capturedAt()).isEqualTo(T0);
    }

    @Test
    void theListIsFilteredByResultCheckAndEntryAndPaged() {
        assertThat(ids(queries.packages(filter("FAIL", null, null, null), 0, 20))).containsExactly("p1");
        assertThat(ids(queries.packages(filter(JdbcPromptInspectionQueries.NOT_INSPECTED, null, null, null), 0, 20)))
                .containsExactly("p2");
        assertThat(ids(queries.packages(filter(null, "FACT_ACCURACY", null, null), 0, 20))).containsExactly("p3", "p1");
        assertThat(ids(queries.packages(filter(null, "PAST_RECORD_NOTATION", null, null), 0, 20))).containsExactly("p1");
        assertThat(ids(queries.packages(filter(null, null, "REQUEST", "Time"), 0, 20))).containsExactly("p3");
        assertThat(ids(queries.packages(filter(null, null, null, "Time"), 0, 20))).containsExactly("p3");

        JdbcPromptInspectionQueries.PackagePage second = queries.packages(filter(null, null, null, null), 1, 1);
        assertThat(second.total()).isEqualTo(3);
        assertThat(ids(second)).containsExactly("p2");
    }

    @Test
    void theOverviewCountsTheLatestResultsOfThePeriod() {
        JdbcPromptInspectionQueries.Overview overview = queries.overview(FROM, TO);

        assertThat(overview.verdicts()).containsEntry("FAIL", 1L).containsEntry("INCOMPLETE", 1L)
                .containsEntry(JdbcPromptInspectionQueries.NOT_INSPECTED, 1L).doesNotContainKey("PASS");
        assertThat(overview.checks()).containsExactlyInAnyOrder(
                new JdbcPromptInspectionQueries.CheckCount("FACT_ACCURACY", 2, 1),
                new JdbcPromptInspectionQueries.CheckCount("PAST_RECORD_NOTATION", 0, 1));
        assertThat(overview.trend()).contains(
                new JdbcPromptInspectionQueries.DayCount(LocalDate.parse("2026-10-11"), "FACT_ACCURACY", 2, 0),
                new JdbcPromptInspectionQueries.DayCount(LocalDate.parse("2026-10-12"), "FACT_ACCURACY", 0, 1));
        assertThat(overview.entries().get(0)).isEqualTo(
                new JdbcPromptInspectionQueries.EntryCount("REQUEST", "Action", 1, 0));
        assertThat(overview.resources()).contains(
                new JdbcPromptInspectionQueries.ResourceCount("exportDocuments", 2, 2));
        assertThat(overview.versions()).contains(
                new JdbcPromptInspectionQueries.VersionCount("2026.10.11-v19.8", "dictionary-v20", "prompt-inspector/1",
                        1, 1, 0, 0, 0, 0),
                new JdbcPromptInspectionQueries.VersionCount("2026.10.11-v19.7", "dictionary-v20", "prompt-inspector/1",
                        1, 0, 1, 0, 0, 0));
    }

    @Test
    void theOverviewAndListCountTheLinesOfEachKindAndTheFindingRowsOfResultsStoredBeforeKinds() {
        // W3-20: a kind a result shows on two lines counts two; a result stored before W3-20 counts its finding rows.
        store.save(result("p2", "prompt-inspector/1", PromptInspectionVerdict.FAIL, List.of(
                mismatch("FACT_ACCURACY", "REQUEST", "Time"), mismatch("FACT_ACCURACY", "REQUEST", "Time"))),
                PromptInspectionTrigger.AUTO, T0.plusSeconds(3700));
        seal("p4", T0.plusSeconds(10800), "user-b", "GET", "/api/documents/D-2", "readDocument", "2026.10.11-v19.8");
        Long earlier = jdbc.queryForObject("""
                insert into prompt_inspection_result (package_id, inspector_version, dictionary_version, layout_version,
                       verdict, checked_count, mismatch_count, unverifiable_count, check_counts_json, inspection_trigger,
                       inspected_at)
                values ('p4', 'prompt-inspector/1', 'dictionary-v20', 'v20-dictionary-blocks', 'FAIL', 4, 1, 0,
                        '[{"checkCode":"FACT_ACCURACY","matched":3,"mismatched":1,"unverifiable":0}]', 'AUTO', ?)
                returning id
                """, Long.class, Timestamp.from(T0.plusSeconds(10900)));
        jdbc.update("insert into prompt_inspection_finding (result_id, check_code, outcome, block_name, entry_name, "
                + "line_number, reason) values (?, 'FACT_ACCURACY', 'MISMATCH', 'REQUEST', 'Time', 4, 'mismatch')",
                earlier);

        JdbcPromptInspectionQueries.Overview overview = queries.overview(FROM, TO);

        assertThat(overview.checks()).contains(new JdbcPromptInspectionQueries.CheckCount("FACT_ACCURACY", 5, 1));
        assertThat(overview.entries()).contains(new JdbcPromptInspectionQueries.EntryCount("REQUEST", "Time", 3, 1));
        assertThat(overview.resources()).contains(new JdbcPromptInspectionQueries.ResourceCount("readDocument", 2, 3));
        assertThat(ids(queries.packages(filter(null, null, "REQUEST", "Time"), 0, 20)))
                .containsExactly("p4", "p3", "p2");
    }

    private void seal(String packageId, Instant capturedAt, String userId, String method, String path, String resourceId,
                      String bundleVersion) {
        jdbc.update("""
                        insert into sealed_evidence_package (package_id, correlation_id, captured_at, user_id,
                               request_facts_json, request_facts_jsonb, prompt_execution_metadata_json, package_hash)
                        values (?, ?, ?, ?, ?, ?::jsonb, ?, ?)
                        """, packageId, "correlation-" + packageId, Timestamp.from(capturedAt), userId,
                facts(method, path, resourceId), facts(method, path, resourceId),
                "{\"governanceDescriptor\":{\"promptBundleVersion\":\"" + bundleVersion + "\"}}", "hash");
    }

    private static String facts(String method, String path, String resourceId) {
        return "{\"httpMethod\":\"" + method + "\",\"requestPath\":\"" + path + "\",\"resourceId\":\"" + resourceId
                + "\"}";
    }

    private static JdbcPromptInspectionQueries.PackageFilter filter(String verdict, String checkCode, String block,
                                                                    String entry) {
        return new JdbcPromptInspectionQueries.PackageFilter(FROM, TO, verdict, checkCode, block, entry);
    }

    private static List<String> ids(JdbcPromptInspectionQueries.PackagePage page) {
        return page.rows().stream().map(JdbcPromptInspectionQueries.PackageRow::packageId).toList();
    }

    private static PromptInspectionFinding mismatch(String check, String block, String entry) {
        return PromptInspectionFinding.builder(check, PromptInspectionOutcome.MISMATCH).block(block).entry(entry)
                .reason("mismatch").build();
    }

    private static PromptInspectionFinding unverifiable(String check, String block, String entry) {
        return PromptInspectionFinding.builder(check, PromptInspectionOutcome.UNVERIFIABLE).block(block).entry(entry)
                .reason("unverifiable").build();
    }

    private static PromptInspectionResult result(String packageId, String version, PromptInspectionVerdict verdict,
                                                 List<PromptInspectionFinding> findings) {
        List<PromptInspectionCheckResult> checks = findings.stream()
                .map(PromptInspectionFinding::checkCode).distinct()
                .map(code -> {
                    List<PromptInspectionFinding> own = findings.stream().filter(item -> code.equals(item.checkCode()))
                            .toList();
                    int mismatched = (int) own.stream()
                            .filter(item -> item.outcome() == PromptInspectionOutcome.MISMATCH).count();
                    return new PromptInspectionCheckResult(code, 3, mismatched, own.size() - mismatched, own);
                })
                .toList();
        return new PromptInspectionResult(packageId, version, "dictionary-v20", "v20-dictionary-blocks", verdict, checks,
                null);
    }
}
