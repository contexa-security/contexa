package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionRecord;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionTrigger;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * W3-20 (storage design A): the findings are stored as kinds - a kind is the inspector version, check, outcome, block,
 * entry and reason - shared by the packages that show them, with the lines of each kind on the result row; the
 * findings table is no longer written; a package keeps the results of its latest and previous inspector versions.
 */
class JdbcPromptInspectionFindingKindTest {

    private static final Instant T0 = Instant.parse("2026-10-13T05:00:00Z");
    private static final String VERSION = "prompt-inspector/16";

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;
    private JdbcPromptInspectionResultStore store;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        for (String statement : InspectionSchema.statements()) {
            jdbc.execute(statement);
        }
        store = new JdbcPromptInspectionResultStore(jdbc,
                new TransactionTemplate(new DataSourceTransactionManager(database.dataSource())), new ObjectMapper());
    }

    @AfterEach
    void tearDown() {
        database.close();
    }

    @Test
    void aResultsFindingsAreKindsWithTheirLinesOnTheResultRow() {
        seal("p1", T0);
        store.save(result("p1", VERSION, List.of(mismatch("Time", 3), mismatch("Time", 9), unverifiable("Network", 5))),
                PromptInspectionTrigger.AUTO, T0.plusSeconds(10));

        assertThat(count("prompt_inspection_finding")).isZero();
        assertThat(jdbc.queryForList("select entry_name, outcome, package_count, line_count from "
                + "prompt_inspection_finding_kind order by entry_name")).extracting(row -> List.of(row.get("entry_name"),
                row.get("outcome"), ((Number) row.get("package_count")).longValue(),
                ((Number) row.get("line_count")).longValue())).containsExactly(
                List.of("Network", "UNVERIFIABLE", 1L, 1L), List.of("Time", "MISMATCH", 1L, 2L));
        assertThat(jdbc.queryForObject("select finding_kinds_json from prompt_inspection_result", String.class))
                .isNotBlank();

        PromptInspectionRecord record = store.findAll("p1").get(0);
        assertThat(record.result().mismatchCount()).isEqualTo(2);
        assertThat(record.result().unverifiableCount()).isEqualTo(1);
        // One kind-level finding a line: the kinds and their lines, without the lines' numbers and values.
        assertThat(record.result().findings()).extracting(PromptInspectionFinding::entry)
                .containsExactly("Time", "Time", "Network");
        assertThat(record.result().findings()).extracting(PromptInspectionFinding::lineNumber).containsOnlyNulls();
    }

    @Test
    void aKindIsSharedByThePackagesThatShowItWithItsFirstAndLastAndExamples() {
        seal("p1", T0);
        seal("p2", T0.plusSeconds(1));
        store.save(result("p1", VERSION, List.of(mismatch("Time", 3))), PromptInspectionTrigger.AUTO, T0.plusSeconds(10));
        store.save(result("p2", VERSION, List.of(mismatch("Time", 4), mismatch("Time", 8))), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(20));

        Map<String, Object> kind = jdbc.queryForMap("select * from prompt_inspection_finding_kind");
        assertThat(((Number) kind.get("package_count")).longValue()).isEqualTo(2);
        assertThat(((Number) kind.get("line_count")).longValue()).isEqualTo(3);
        assertThat(kind.get("first_package_id")).isEqualTo("p1");
        assertThat(kind.get("last_package_id")).isEqualTo("p2");
        assertThat((String) kind.get("example_package_ids")).contains("p1").contains("p2");
        assertThat(kind.get("example_expected")).isEqualTo("expected 3");
    }

    @Test
    void aKindKeepsItsLatestFivePackagesAsExamples() throws Exception {
        for (int number = 1; number <= 6; number++) {
            seal("p" + number, T0.plusSeconds(number));
            store.save(result("p" + number, VERSION, List.of(mismatch("Time", number))), PromptInspectionTrigger.AUTO,
                    T0.plusSeconds(10L * number));
        }

        Map<String, Object> kind = jdbc.queryForMap("select * from prompt_inspection_finding_kind");
        assertThat(((Number) kind.get("package_count")).longValue()).isEqualTo(6);
        assertThat(kind.get("first_package_id")).isEqualTo("p1");
        assertThat(kind.get("last_package_id")).isEqualTo("p6");
        assertThat(new ObjectMapper().readValue((String) kind.get("example_package_ids"), List.class))
                .containsExactly("p2", "p3", "p4", "p5", "p6");
        assertThat(kind.get("example_expected")).isEqualTo("expected 1");
    }

    @Test
    void aResultThatCannotBeStoredLeavesNoKindCounted() {
        // The package was never sealed (or went meanwhile): the result row cannot refer to it, and the kinds it
        // counted are taken back with it.
        assertThatThrownBy(() -> store.save(result("gone", VERSION, List.of(mismatch("Time", 3))),
                PromptInspectionTrigger.AUTO, T0.plusSeconds(10))).isInstanceOf(DataAccessException.class);

        assertThat(count("prompt_inspection_finding_kind")).isZero();
        assertThat(count("prompt_inspection_result")).isZero();
    }

    @Test
    void savingAPackageAgainOrRemovingItsResultKeepsTheKindCountsRight() {
        seal("p1", T0);
        seal("p2", T0.plusSeconds(1));
        store.save(result("p1", VERSION, List.of(mismatch("Time", 3))), PromptInspectionTrigger.AUTO, T0.plusSeconds(10));
        store.save(result("p2", VERSION, List.of(mismatch("Time", 4))), PromptInspectionTrigger.AUTO, T0.plusSeconds(20));
        store.save(result("p1", VERSION, List.of(mismatch("Time", 3), mismatch("Time", 7))),
                PromptInspectionTrigger.OPERATOR, T0.plusSeconds(30));

        assertThat(jdbc.queryForObject("select package_count from prompt_inspection_finding_kind", Long.class))
                .isEqualTo(2);
        assertThat(jdbc.queryForObject("select line_count from prompt_inspection_finding_kind", Long.class))
                .isEqualTo(3);

        store.removeResults(VERSION, T0, T0.plusSeconds(1), 100);
        assertThat(count("prompt_inspection_finding_kind")).isZero();
    }

    @Test
    void aPackageKeepsTheResultsOfItsLatestAndPreviousInspectorVersions() {
        seal("p1", T0);
        store.save(result("p1", "prompt-inspector/14", List.of(mismatch("Time", 3))), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(10));
        store.save(result("p1", "prompt-inspector/15", List.of(mismatch("Time", 3))), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(20));
        store.save(result("p1", VERSION, List.of(unverifiable("Network", 5))), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(30));

        assertThat(store.findAll("p1")).extracting(record -> record.result().inspectorVersion())
                .containsExactly(VERSION, "prompt-inspector/15");
        assertThat(jdbc.queryForList("select inspector_version from prompt_inspection_finding_kind order by 1",
                String.class)).containsExactly("prompt-inspector/15", VERSION);
    }

    private void seal(String packageId, Instant capturedAt) {
        jdbc.update("insert into sealed_evidence_package (package_id, correlation_id, captured_at, package_hash) "
                + "values (?, ?, ?, ?)", packageId, "correlation-" + packageId, Timestamp.from(capturedAt), "hash");
    }

    private int count(String table) {
        Integer count = jdbc.queryForObject("select count(*) from " + table, Integer.class);
        return count == null ? 0 : count;
    }

    private static PromptInspectionFinding mismatch(String entry, int line) {
        return PromptInspectionFinding.builder("FACT_ACCURACY", PromptInspectionOutcome.MISMATCH).block("REQUEST")
                .entry(entry).lineNumber(line).expected("expected " + line).actual("actual " + line)
                .sourceRef("canonicalContext.requestObservedAt").reason("the line is not the sealed one").build();
    }

    private static PromptInspectionFinding unverifiable(String entry, int line) {
        return PromptInspectionFinding.builder("FACT_ACCURACY", PromptInspectionOutcome.UNVERIFIABLE).block("REQUEST")
                .entry(entry).lineNumber(line).actual("actual " + line).sourceRef("canonicalContext.location")
                .reason("the band is not sealed").build();
    }

    private static PromptInspectionResult result(String packageId, String version,
                                                 List<PromptInspectionFinding> findings) {
        int mismatched = (int) findings.stream().filter(item -> item.outcome() == PromptInspectionOutcome.MISMATCH)
                .count();
        int unverifiable = findings.size() - mismatched;
        List<PromptInspectionCheckResult> checks = List.of(
                new PromptInspectionCheckResult("SEAL_INTEGRITY", 9, 0, 0, List.of()),
                new PromptInspectionCheckResult("FACT_ACCURACY", 30, mismatched, unverifiable, findings));
        PromptInspectionVerdict verdict = mismatched > 0 ? PromptInspectionVerdict.FAIL
                : unverifiable > 0 ? PromptInspectionVerdict.INCOMPLETE : PromptInspectionVerdict.PASS;
        return new PromptInspectionResult(packageId, version, "v20@6a46c80cd3a1", "v20-dictionary-blocks", verdict,
                checks, null);
    }
}
