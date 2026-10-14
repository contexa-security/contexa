package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionRecord;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The JDBC store of inspection results on PostgreSQL, with the tables as the OSS schema declares them: one result per
 * sealed package and inspector version with its findings, removed with the package, and the automatic round's choice
 * of the oldest uninspected packages in a stable sample.
 */
class JdbcPromptInspectionResultStoreTest {

    private static final Instant T0 = Instant.parse("2026-10-12T05:00:00Z");
    private static final String VERSION = "prompt-inspector/1";

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
    void theUninspectedPackagesAreTheOldestWithoutAResultOfThisInspectorVersion() {
        seal("p3", T0.plusSeconds(30));
        seal("p1", T0.plusSeconds(10));
        seal("p2", T0.plusSeconds(20));
        store.save(result("p1", VERSION, List.of()), PromptInspectionTrigger.AUTO, T0.plusSeconds(40));
        store.save(result("p2", "prompt-inspector/0", List.of()), PromptInspectionTrigger.AUTO, T0.plusSeconds(40));

        assertThat(store.findUninspectedPackageIds(VERSION, 10, 100)).containsExactly("p2", "p3");
        assertThat(store.findUninspectedPackageIds(VERSION, 1, 100)).containsExactly("p2");
    }

    @Test
    void aStoredResultReadsBackAsItWasGivenWithItsTriggerAndTime() {
        seal("p1", T0);
        PromptInspectionResult given = result("p1", VERSION, List.of(
                PromptInspectionFinding.builder("FACT_ACCURACY", PromptInspectionOutcome.MISMATCH).block("REQUEST")
                        .entry("Action").factId("F3").lineNumber(12).expected("EXPORT").actual("READ")
                        .sourceRef("canonicalContext.resource").reason("the line says another action").build(),
                PromptInspectionFinding.builder("FACT_ACCURACY", PromptInspectionOutcome.UNVERIFIABLE)
                        .sourceRef("canonicalContext.requestObservedAt").reason("the request time is not sealed")
                        .build(),
                PromptInspectionFinding.builder("FACT_ACCURACY", PromptInspectionOutcome.MISMATCH).block("SESSION")
                        .entry("LoginMethod").lineNumber(20).expected("password").actual("token")
                        .reason("a line without a fact id keeps its line number").build()));
        Instant at = Instant.parse("2026-10-12T06:00:00.123456Z");

        store.save(given, PromptInspectionTrigger.OPERATOR, at);

        PromptInspectionRecord record = store.findAll("p1").get(0);
        assertThat(record.resultId()).isNotNull();
        assertThat(record.trigger()).isEqualTo(PromptInspectionTrigger.OPERATOR);
        assertThat(record.inspectedAt()).isEqualTo(at);
        // W3-20: a stored result keeps its counts and its findings as kinds with their lines; the lines' numbers and
        // values were of this package only and are not stored.
        assertThat(record.result().verdict()).isEqualTo(given.verdict());
        assertThat(record.result().checks()).extracting(PromptInspectionCheckResult::checkCode,
                        PromptInspectionCheckResult::matched, PromptInspectionCheckResult::mismatched,
                        PromptInspectionCheckResult::unverifiable)
                .containsExactlyElementsOf(given.checks().stream().map(check -> tuple(check.checkCode(),
                        check.matched(), check.mismatched(), check.unverifiable())).toList());
        assertThat(record.result().findings()).extracting(PromptInspectionFinding::block, PromptInspectionFinding::entry,
                        PromptInspectionFinding::reason, PromptInspectionFinding::lineNumber)
                .containsExactly(tuple("REQUEST", "Action", "the line says another action", null),
                        tuple(null, null, "the request time is not sealed", null),
                        tuple("SESSION", "LoginMethod", "a line without a fact id keeps its line number", null));
        assertThat(jdbc.queryForObject("select checked_count from prompt_inspection_result", Integer.class))
                .isEqualTo(given.matchedCount() + given.mismatchCount() + given.unverifiableCount());
    }

    @Test
    void savingAgainForTheSameVersionReplacesTheResultAndItsFindings() {
        seal("p1", T0);
        store.save(result("p1", VERSION, List.of(finding("first"), finding("second"))), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(1));
        PromptInspectionResult again = result("p1", VERSION, List.of());

        store.save(again, PromptInspectionTrigger.OPERATOR, T0.plusSeconds(2));

        assertThat(count("prompt_inspection_result")).isEqualTo(1);
        assertThat(count("prompt_inspection_finding")).isZero();
        assertThat(store.findAll("p1").get(0).result()).isEqualTo(again);
    }

    @Test
    void aResultOfAnotherInspectorVersionIsKeptBesideAndTheLatestIsTheNewest() {
        seal("p1", T0);
        store.save(result("p1", "prompt-inspector/0", List.of()), PromptInspectionTrigger.AUTO, T0.plusSeconds(1));
        store.save(result("p1", VERSION, List.of()), PromptInspectionTrigger.AUTO, T0.plusSeconds(2));

        assertThat(count("prompt_inspection_result")).isEqualTo(2);
        assertThat(store.findAll("p1").get(0).result().inspectorVersion()).isEqualTo(VERSION);
    }

    @Test
    void everyStoredResultOfAPackageReadsNewestFirstWithItsOwnFindings() {
        seal("p1", T0);
        store.save(result("p1", "prompt-inspector/0", List.of(finding("old"))), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(1));
        store.save(result("p1", VERSION, List.of(finding("new one"), finding("new two"))),
                PromptInspectionTrigger.OPERATOR, T0.plusSeconds(2));

        List<PromptInspectionRecord> all = store.findAll("p1");

        assertThat(all).extracting(record -> record.result().inspectorVersion())
                .containsExactly(VERSION, "prompt-inspector/0");
        assertThat(all.get(0).trigger()).isEqualTo(PromptInspectionTrigger.OPERATOR);
        assertThat(all.get(0).result().findings()).extracting(PromptInspectionFinding::reason)
                .containsExactly("new one", "new two");
        assertThat(all.get(1).result().findings()).extracting(PromptInspectionFinding::reason).containsExactly("old");
        assertThat(store.findAll("none")).isEmpty();
    }

    @Test
    void removingTheSealedPackageRemovesItsResultsAndFindings() {
        seal("p1", T0);
        store.save(result("p1", VERSION, List.of(finding("one"))), PromptInspectionTrigger.AUTO, T0.plusSeconds(1));

        jdbc.update("delete from sealed_evidence_package where package_id = ?", "p1");

        assertThat(count("prompt_inspection_result")).isZero();
        assertThat(count("prompt_inspection_finding")).isZero();
        assertThat(store.findAll("p1")).isEmpty();
    }

    @Test
    void aResultWhoseFindingsCannotBeStoredLeavesNothingAndThePackageUninspected() {
        seal("p1", T0);
        PromptInspectionFinding tooLong = PromptInspectionFinding.builder("X".repeat(200),
                PromptInspectionOutcome.MISMATCH).reason("a check code longer than its column").build();

        assertThatThrownBy(() -> store.save(result("p1", VERSION, List.of(tooLong)), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(1))).isInstanceOf(RuntimeException.class);

        assertThat(count("prompt_inspection_result")).isZero();
        assertThat(store.findUninspectedPackageIds(VERSION, 10, 100)).containsExactly("p1");
    }

    /** R1b-6: a period's results of this version are removed with their findings; other versions are kept. */
    @Test
    void aPeriodsResultsOfThisVersionAreRemovedSoTheRoundInspectsThemAgain() {
        seal("p1", T0.plusSeconds(10));
        seal("p2", T0.plusSeconds(20));
        seal("p3", T0.plusSeconds(30));
        for (String packageId : List.of("p1", "p2", "p3")) {
            store.save(result(packageId, VERSION, List.of(finding("kept"))), PromptInspectionTrigger.AUTO,
                    T0.plusSeconds(40));
        }
        store.save(result("p2", "prompt-inspector/0", List.of()), PromptInspectionTrigger.AUTO, T0.plusSeconds(41));

        assertThat(store.countPeriod(VERSION, T0, T0.plusSeconds(25), 100))
                .isEqualTo(new PromptInspectionResultStore.PeriodCount(2, 0));
        assertThat(store.removeResults(VERSION, T0, T0.plusSeconds(25), 100)).isEqualTo(2);

        assertThat(store.findUninspectedPackageIds(VERSION, 10, 100)).containsExactly("p1", "p2");
        assertThat(store.countPeriod(VERSION, T0, T0.plusSeconds(25), 100))
                .isEqualTo(new PromptInspectionResultStore.PeriodCount(2, 2));
        assertThat(store.findAll("p2")).extracting(record -> record.result().inspectorVersion())
                .containsExactly("prompt-inspector/0");
        // W3-20: the kind the removed results showed is left with the one package that still shows it.
        assertThat(jdbc.queryForObject("select package_count from prompt_inspection_finding_kind", Long.class))
                .isEqualTo(1);
    }

    /** R1b-6: outside the round's sample nothing is removed, since the round would not inspect it again. */
    @Test
    void aPeriodsRemovalKeepsToTheRoundsSample() {
        for (int index = 0; index < 200; index++) {
            seal("package-" + index, T0.plusSeconds(index));
            store.save(result("package-" + index, VERSION, List.of()), PromptInspectionTrigger.AUTO, T0.plusSeconds(500));
        }

        PromptInspectionResultStore.PeriodCount half = store.countPeriod(VERSION, T0, T0.plusSeconds(300), 50);
        assertThat(half.packages()).isBetween(60L, 140L);
        assertThat(store.removeResults(VERSION, T0, T0.plusSeconds(300), 50)).isEqualTo((int) half.packages());

        List<String> again = store.findUninspectedPackageIds(VERSION, 1000, 100);
        assertThat(again).hasSize((int) half.packages());
        assertThat(store.findUninspectedPackageIds(VERSION, 1000, 50)).isEqualTo(again);
    }

    @Test
    void theSampleIsAStableShareOfThePackages() {
        for (int index = 0; index < 200; index++) {
            seal("package-" + index, T0.plusSeconds(index));
        }

        List<String> all = store.findUninspectedPackageIds(VERSION, 1000, 100);
        List<String> half = store.findUninspectedPackageIds(VERSION, 1000, 50);

        assertThat(all).hasSize(200);
        assertThat(half).hasSizeBetween(60, 140);
        assertThat(all).containsAll(half);
        assertThat(store.findUninspectedPackageIds(VERSION, 1000, 50)).isEqualTo(half);
        assertThat(store.findUninspectedPackageIds(VERSION, 1000, 1)).hasSizeLessThan(half.size());
    }

    /**
     * R4-S5: a package captured before the given time goes when its latest result found nothing wrong (PASS or
     * NOT_APPLICABLE) and no official verification names it; a failed, incomplete, erroneous or uninspected package,
     * one whose latest result found something, and one an official verification names keep the default retention.
     */
    @Test
    void theShortRetentionRemovesTheOldPackagesWhoseLatestResultFoundNothingWrong() {
        Instant before = T0.plusSeconds(100);
        List<String> ids = List.of("pass", "not-applicable", "fail", "incomplete", "error", "uninspected",
                "pass-then-fail", "fail-then-pass", "pass-in-official-run", "pass-in-run-ledger");
        for (int index = 0; index < ids.size(); index++) {
            seal(ids.get(index), T0.plusSeconds(index + 1));
        }
        seal("pass-recent", before.plusSeconds(1));
        for (String id : List.of("pass", "pass-in-official-run", "pass-in-run-ledger", "pass-recent")) {
            store.save(verdict(id, VERSION, PromptInspectionVerdict.PASS), PromptInspectionTrigger.AUTO,
                    T0.plusSeconds(200));
        }
        store.save(verdict("not-applicable", VERSION, PromptInspectionVerdict.NOT_APPLICABLE),
                PromptInspectionTrigger.AUTO, T0.plusSeconds(200));
        store.save(verdict("fail", VERSION, PromptInspectionVerdict.FAIL), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(200));
        store.save(verdict("incomplete", VERSION, PromptInspectionVerdict.INCOMPLETE), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(200));
        store.save(verdict("error", VERSION, PromptInspectionVerdict.ERROR), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(200));
        store.save(verdict("pass-then-fail", "prompt-inspector/0", PromptInspectionVerdict.PASS),
                PromptInspectionTrigger.AUTO, T0.plusSeconds(200));
        store.save(verdict("pass-then-fail", VERSION, PromptInspectionVerdict.FAIL), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(300));
        store.save(verdict("fail-then-pass", "prompt-inspector/0", PromptInspectionVerdict.FAIL),
                PromptInspectionTrigger.AUTO, T0.plusSeconds(200));
        store.save(verdict("fail-then-pass", VERSION, PromptInspectionVerdict.PASS), PromptInspectionTrigger.AUTO,
                T0.plusSeconds(300));
        jdbc.update("insert into official_verification_run_batch (aggregate_run_id, package_id, tenant_id, scope_type, "
                + "expected_metric_count, final_decision) values ('run-1', 'pass-in-official-run', 'tenant-1', "
                + "'PACKAGE', 12, 'PASSED')");
        jdbc.update("insert into verification_run_ledger (run_id, user_id, metric_code, execution_path, package_id) "
                + "values ('ledger-1', 'user-1', 'M01', 'official', 'pass-in-run-ledger')");

        assertThat(store.removeCleanPackagesCapturedBefore(before, 100)).isEqualTo(3);

        assertThat(jdbc.queryForList("select package_id from sealed_evidence_package order by captured_at",
                String.class)).containsExactly("fail", "incomplete", "error", "uninspected", "pass-then-fail",
                "pass-in-official-run", "pass-in-run-ledger", "pass-recent");
        assertThat(jdbc.queryForObject("select count(*) from prompt_inspection_result where package_id in "
                + "('pass', 'not-applicable', 'fail-then-pass')", Integer.class)).isZero();
        // fail, incomplete, error, the two of pass-then-fail, and the three that keep the default retention.
        assertThat(count("prompt_inspection_result")).isEqualTo(8);
    }

    /** R4-S5: one call removes at most the limit, oldest capture first. */
    @Test
    void theShortRetentionRemovesAtMostTheLimitOldestFirst() {
        seal("c", T0.plusSeconds(3));
        seal("a", T0.plusSeconds(1));
        seal("b", T0.plusSeconds(2));
        for (String id : List.of("a", "b", "c")) {
            store.save(verdict(id, VERSION, PromptInspectionVerdict.PASS), PromptInspectionTrigger.AUTO,
                    T0.plusSeconds(10));
        }

        assertThat(store.removeCleanPackagesCapturedBefore(T0.plusSeconds(100), 2)).isEqualTo(2);
        assertThat(jdbc.queryForList("select package_id from sealed_evidence_package", String.class))
                .containsExactly("c");
        assertThat(store.removeCleanPackagesCapturedBefore(T0.plusSeconds(100), 2)).isEqualTo(1);
        assertThat(count("sealed_evidence_package")).isZero();
    }

    /**
     * R4-S5: a NOT_APPLICABLE result can hold findings that could not be checked; the short retention takes a removed
     * result out of its finding kinds as a period's removal does.
     */
    @Test
    void theShortRetentionTakesTheRemovedResultsOutOfTheirFindingKinds() {
        seal("old", T0);
        seal("recent", T0.plusSeconds(200));
        for (String id : List.of("old", "recent")) {
            PromptInspectionFinding unverifiable = PromptInspectionFinding.builder("FACT_ACCURACY",
                            PromptInspectionOutcome.UNVERIFIABLE).sourceRef("canonicalContext.requestObservedAt")
                    .reason("the request time is not sealed").build();
            store.save(new PromptInspectionResult(id, VERSION, "dictionary-v20", "v20-dictionary-blocks",
                    PromptInspectionVerdict.NOT_APPLICABLE, List.of(new PromptInspectionCheckResult("FACT_ACCURACY", 7,
                    0, 1, List.of(unverifiable))), null), PromptInspectionTrigger.AUTO, T0.plusSeconds(300));
        }

        assertThat(store.removeCleanPackagesCapturedBefore(T0.plusSeconds(100), 100)).isEqualTo(1);

        assertThat(jdbc.queryForObject("select package_count from prompt_inspection_finding_kind", Long.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("select line_count from prompt_inspection_finding_kind", Long.class))
                .isEqualTo(1);
    }

    private void seal(String packageId, Instant capturedAt) {
        jdbc.update("insert into sealed_evidence_package (package_id, correlation_id, captured_at, package_hash) "
                + "values (?, ?, ?, ?)", packageId, "correlation-" + packageId, Timestamp.from(capturedAt), "hash");
    }

    private int count(String table) {
        Integer count = jdbc.queryForObject("select count(*) from " + table, Integer.class);
        return count == null ? 0 : count;
    }

    private static PromptInspectionFinding finding(String reason) {
        return PromptInspectionFinding.builder("DICTIONARY_CONTRACT", PromptInspectionOutcome.MISMATCH)
                .block("SESSION").entry("LoginMethod").lineNumber(20).expected("an entry line").actual("text")
                .reason(reason).build();
    }

    private static PromptInspectionResult verdict(String packageId, String version, PromptInspectionVerdict verdict) {
        return new PromptInspectionResult(packageId, version, "dictionary-v20", "v20-dictionary-blocks", verdict,
                List.of(new PromptInspectionCheckResult("SEAL_INTEGRITY", 10, 0, 0, List.of())),
                verdict == PromptInspectionVerdict.ERROR ? "a check failed" : null);
    }

    private static PromptInspectionResult result(String packageId, String version,
                                                 List<PromptInspectionFinding> findings) {
        int mismatched = (int) findings.stream().filter(item -> item.outcome() == PromptInspectionOutcome.MISMATCH)
                .count();
        int unverifiable = findings.size() - mismatched;
        String code = findings.isEmpty() ? "FACT_ACCURACY" : findings.get(0).checkCode();
        List<PromptInspectionCheckResult> checks = List.of(
                new PromptInspectionCheckResult("SEAL_INTEGRITY", 10, 0, 0, List.of()),
                new PromptInspectionCheckResult(code, 7, mismatched, unverifiable, findings));
        PromptInspectionVerdict verdict = mismatched > 0 ? PromptInspectionVerdict.FAIL
                : unverifiable > 0 ? PromptInspectionVerdict.INCOMPLETE : PromptInspectionVerdict.PASS;
        return new PromptInspectionResult(packageId, version, "dictionary-v20", "v20-dictionary-blocks", verdict, checks,
                null);
    }
}
