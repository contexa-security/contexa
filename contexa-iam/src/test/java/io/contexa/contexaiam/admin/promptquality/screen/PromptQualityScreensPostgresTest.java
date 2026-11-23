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
package io.contexa.contexaiam.admin.promptquality.screen;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseRationale;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityRate;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.measure.MeasuredQualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityResourceClasses;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityRunLine;
import io.contexa.contexaiam.admin.promptquality.measure.QualityModelSetting;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.CaseRow;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.ChangeRow;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Detail;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.ListView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.CaseAnswers;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.CompareView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.GradeMetrics;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Metric;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.RunRow;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.RunView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.RunsView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.SplitRow;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;
import static org.mockito.Mockito.mock;

/**
 * Quality plan 3.2, 3.3, 3.8 on a database with the schema of a new installation: the reads the two screens added
 * (the measurements of the scope page by page, a case's answers with the facts they cited, the measurements that
 * answered a case, the published bundles) and what the screens compose from them: the list of the cases with the
 * bundle, the targets and what the version in use answered; a case with the changes of its answer and what they alone
 * did; the measurements and the trials in one list; one measurement by basis and grade; and two versions compared as
 * the quality gate compares them, with one case's answers side by side.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityScreensPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String PLATFORM = PromptVersionService.PLATFORM_SCOPE;
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final Instant NOW = Instant.parse("2026-11-22T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final Map<String, String> SETTINGS = Map.of("layer1.model", "model-a");
    private static final String HASH = QualityModelSetting.hash(SETTINGS);
    private static final String FINDINGS = "[{\"code\":\"NO_COVERING_RECORD\",\"fact\":\"F5\",\"outcome\":\"MATCH\","
            + "\"present\":true,\"reason\":\"no approval\"}]";
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private PromptVersionService versions;
    private PromptQualityCases cases;
    private PromptQualityMeasurements runner;
    private PromptVersionTrials trials;
    private ExecutorService trialThread;
    private PromptQualityCaseScreen caseScreen;
    private PromptQualityMeasureScreen measureScreen;

    @BeforeAll
    static void aDatabaseWithTheSchema() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        try (Connection connection = database.dataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.setEscapeProcessing(false);
            statement.execute(schema);
        }
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    /** v1.0 is the product version, decisions run it (nothing else is labelled); v2.0 is an organization's. */
    @BeforeEach
    void theServices() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_case_cause, ctxa_prompt_version_measure_prompt,"
                + " ctxa_prompt_version_measure_answer, ctxa_prompt_version_measure, ctxa_prompt_version_case_set_member,"
                + " ctxa_prompt_version_case_set, ctxa_prompt_version_case_change, ctxa_prompt_version_case,"
                + " ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_governance_registry, ctxa_zt_stats_hourly CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), TARGETS,
                PromptVersionAudit.none(), CLOCK);
        versions.registerProducts(null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Payroll\nsystem:\n"
                + "  - key: how-to-judge\n    text: |\n      1. Weigh the payroll roster first.\n",
                PromptVersionRecord.SCREEN, null, "admin", null);
        cases = new PromptQualityCases(() -> jdbc, JSON, true, PromptVersionAudit.none(), CLOCK, null, null);
        runner = new PromptQualityMeasurements(() -> jdbc, versions, cases,
                (actor, given, format, version, user, organization, scope, timeZone) -> {
                    throw new IllegalStateException("Nothing is replayed in this test");
                }, new PromptQualityRunLine(), atMostFor -> Optional.empty(), () -> SETTINGS,
                () -> QualityClosingRules.DEFAULTS,
                new PromptQualityMeasurements.Settings(3, 1, 0, Duration.ZERO, 3000, Duration.ofSeconds(60)), JSON,
                CLOCK, "server-a");
        trialThread = Executors.newSingleThreadExecutor();
        trials = new PromptVersionTrials(() -> jdbc, versions, mock(PromptVersionTrials.Replayer.class), trialThread,
                null, null);
        PromptVersionConsole console = new PromptVersionConsole(versions, () -> trials, () -> null, () -> jdbc,
                () -> null, () -> null, () -> null, () -> null, () -> null, () -> null, () -> null, null, () -> null,
                PromptVersionAudit.none(), CLOCK);
        MeasuredQualityGateSource source = new MeasuredQualityGateSource(() -> jdbc, versions, cases, () -> runner, null);
        PromptQualityResourceClasses classes = new PromptQualityResourceClasses(() -> jdbc, cases, () -> runner,
                () -> source, CLOCK);
        caseScreen = new PromptQualityCaseScreen(cases, () -> runner, () -> classes, () -> console, () -> null, null,
                CLOCK);
        measureScreen = new PromptQualityMeasureScreen(() -> runner, cases, () -> classes, () -> source,
                () -> console, () -> versions, () -> trials, JSON, CLOCK);
    }

    @AfterEach
    void closeTheServices() {
        runner.close();
        trials.close();
        trialThread.shutdownNow();
    }

    private static QualityCaseExpectation answer(Set<QualityAction> allowed, String why) {
        return new QualityCaseExpectation(allowed, null, QualityCaseClass.THREAT, QualityCaseKind.OUTSIDER,
                new QualityCaseRationale(why, null), List.of());
    }

    /** A case of ours copied from A1, its answer set by lee, waiting for another administrator. */
    private PromptQualityCases.Kept ours(String why) {
        return cases.copy(null, PROMPT, "A1", null, answer(Set.of(QualityAction.BLOCK, QualityAction.CHALLENGE), why),
                QualityCaseGrade.ORDINARY, "lee");
    }

    private static String sound(QualityCase item) {
        return item.shouldStop() ? "BLOCK" : "ALLOW";
    }

    /** A finished measurement as its runner writes it: every case of the set in three runs, the missed ones allowed. */
    private long measured(PromptQualityCases.PublishedSet set, int version, Instant at, Set<String> missed) {
        String content = versions.find(PLATFORM, PROMPT, version).orElseThrow().contentHash();
        long id = jdbc.queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key,"
                + " version_number, version_content_hash, case_set_id, case_set_version, repeats, settings_hash,"
                + " settings, model_setting, closing_rules, status, planned_answers, reusable_answers,"
                + " expected_min_calls, expected_max_calls, call_limit, created_by, created_at) values (?, ?, ?, ?, ?,"
                + " ?, 3, ?, '{}', ?, 'test', ?, 213, 0, 213, 852, 0, 'admin', ?) returning id", Long.class, PLATFORM,
                PROMPT, version, content, set.id(), set.version(), HASH, "settings=" + HASH + ";models=model-a",
                PromptQualityMeasurements.DONE, Timestamp.from(at));
        for (QualityCase item : cases.read(set).cases().cases()) {
            for (int run = 1; run <= 3; run++) {
                String action = missed.contains(item.key()) ? "ALLOW" : sound(item);
                jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                        + " case_content_hash, version_number, version_content_hash, settings_hash, run_number,"
                        + " first_action, final_action, cited_facts, accurate_cited_facts, citation_findings,"
                        + " decision_ms, answer_tokens, answered_model, created_at)"
                        + " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, 7000, 130, 'model-a', ?)", id, PLATFORM,
                        item.key(), item.contentHash(), version, content, HASH, run, action, action,
                        missed.contains(item.key()) ? FINDINGS : null, Timestamp.from(at));
            }
        }
        return id;
    }

    private void trial(int candidate, int reference, String status, Instant at) {
        jdbc.update("insert into ctxa_prompt_version_trial (registry_scope, prompt_key, candidate_number,"
                + " reference_number, requested_count, actual_count, status, created_by, created_at) values"
                + " (?, ?, ?, ?, 20, 20, ?, 'admin', ?)", PLATFORM, PROMPT, candidate, reference, status,
                Timestamp.from(at));
    }

    @Test
    void theReadsOfTheScreensAreTheScopesNewestFirst() {
        PromptQualityCases.PublishedSet first = cases.publish(null, PROMPT, "kim");
        PromptQualityCases.Kept kept = ours("ours");
        cases.confirm(null, PROMPT, kept.key(), "kim");
        PromptQualityCases.PublishedSet second = cases.publish(null, PROMPT, "kim");
        long older = measured(first, 1, NOW.minusSeconds(300), Set.of());
        long newer = measured(second, 2, NOW.minusSeconds(100), Set.of("A1"));

        assertThat(cases.publishedSets(null, PROMPT, 10)).extracting(PromptQualityCases.PublishedSet::id)
                .containsExactly(second.id(), first.id());
        assertThat(runner.list(null, PROMPT, 0, 10)).extracting(PromptQualityMeasurements.Measure::id)
                .containsExactly(newer, older);
        assertThat(runner.list(null, PROMPT, 1, 10)).extracting(PromptQualityMeasurements.Measure::id)
                .containsExactly(older);
        assertThat(runner.list("tenant-a", PROMPT, 0, 10)).isEmpty();
        assertThat(runner.caseAnswers(newer, "A1")).extracting(PromptQualityMeasurements.CaseAnswer::run)
                .containsExactly(1, 2, 3);
        assertThat(runner.caseAnswers(newer, "A1")).allSatisfy(answer -> {
            assertThat(answer.firstAction()).isEqualTo(QualityAction.ALLOW);
            assertThat(answer.citationFindings()).contains("NO_COVERING_RECORD");
        });
        assertThat(runner.caseHistory(null, PROMPT, "A1", 20)).extracting(history -> history.measure().id())
                .containsExactly(newer, older);
        assertThat(runner.caseHistory(null, PROMPT, kept.key(), 20)).extracting(history -> history.measure().id())
                .containsExactly(newer);
        assertThat(runner.caseHistory(null, PROMPT, "A1", 20).get(0).answers()).hasSize(3);
        assertThat(runner.modelSettings()).isEqualTo(SETTINGS);
    }

    @Test
    void theListOfCasesCountsTheBundleTheTargetsAndWhatTheVersionInUseAnswered() {
        PromptQualityCases.Kept confirmed = ours("confirmed");
        cases.confirm(null, PROMPT, confirmed.key(), "kim");
        PromptQualityCases.Kept waiting = ours("waiting");
        PromptQualityCases.PublishedSet set = cases.publish(null, PROMPT, "kim");
        long used = measured(set, 1, NOW.minusSeconds(60), Set.of("A1"));

        ListView view = caseScreen.list(null, "kim");

        assertThat(view.counts()).isEqualTo(new PromptQualityCaseViews.Counts(72, 70, 0, 2, 1));
        assertThat(view.bundle().cases()).isEqualTo(71);
        assertThat(view.addedSince()).isZero();
        assertThat(view.sufficiency().stopRoots()).isEqualTo(25);
        assertThat(view.sufficiency().passRoots()).isEqualTo(10);
        assertThat(view.sufficiency().stopCases()).isEqualTo(56);
        assertThat(view.sufficiency().stopTarget()).isEqualTo(200);
        assertThat(view.sufficiency().passTarget()).isEqualTo(300);
        assertThat(view.sufficiency().power()).isBetween(0.0, view.sufficiency().powerAtTarget());
        assertThat(view.usedVersion()).isEqualTo("v1.0");
        assertThat(view.measureId()).isEqualTo(used);
        assertThat(view.rows().get(0).key()).isEqualTo(waiting.key());
        assertThat(view.rows()).filteredOn(row -> row.key().equals(waiting.key())).extracting(CaseRow::now)
                .containsExactly("PENDING");
        assertThat(view.rows()).filteredOn(row -> row.key().equals("A1")).extracting(CaseRow::now)
                .containsExactly("MISS");
        assertThat(view.rows()).filteredOn(row -> row.key().equals(confirmed.key())).extracting(CaseRow::now,
                CaseRow::root, CaseRow::readonly).containsExactly(tuple("HIT", "A1", false));
        assertThat(view.rows()).filteredOn(CaseRow::readonly).hasSize(70);
        assertThat(view.coverage().caseSetId()).isEqualTo(set.id());
        assertThat(view.coverage().coverage().classes()).extracting(row -> row.resourceClass())
                .startsWith("CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC");

        PromptQualityCases.Kept later = ours("later");
        cases.confirm(null, PROMPT, later.key(), "kim");
        assertThat(caseScreen.list(null, "kim").addedSince()).isEqualTo(1);
        assertThat(caseScreen.list("tenant-a", "kim").counts().all()).isEqualTo(70);
    }

    /** Plan 3.2: a case's answer events in order, and the answers that got better by changing the answer alone. */
    @Test
    void aCaseShowsItsAnswerChangesAndWhatTheyAloneDid() {
        PromptQualityCases.Kept kept = ours("first");
        cases.confirm(null, PROMPT, kept.key(), "kim");
        PromptQualityCases.PublishedSet set = cases.publish(null, PROMPT, "kim");
        measured(set, 1, NOW.minusSeconds(60), Set.of(kept.key()));
        cases.changeAnswer(null, PROMPT, kept.key(), answer(Set.of(QualityAction.BLOCK, QualityAction.CHALLENGE,
                QualityAction.ALLOW), "allowing is right too"), QualityCaseGrade.ORDINARY, "lee");

        Detail byKim = caseScreen.detail(null, kept.key(), "kim", Locale.KOREAN).orElseThrow();
        Detail byLee = caseScreen.detail(null, kept.key(), "lee", Locale.ENGLISH).orElseThrow();

        assertThat(byKim.changes()).extracting(ChangeRow::kind).containsExactly("SUBMITTED", "CHANGED");
        assertThat(byKim.changes().get(1).previous()).containsExactly("CHALLENGE", "BLOCK");
        assertThat(byKim.changes().get(1).why()).isEqualTo("allowing is right too");
        assertThat(byKim.improvedByEdit()).isEqualTo(new PromptQualityCaseViews.Improved(1, 3, 3, 0));
        assertThat(byKim.results()).hasSize(1);
        assertThat(byKim.results().get(0).actions()).containsExactly("ALLOW", "ALLOW", "ALLOW");
        assertThat(byKim.row().pending()).isTrue();
        assertThat(byKim.canConfirm()).isTrue();
        assertThat(byLee.canConfirm()).isFalse();
        assertThat(byKim.privacy()).isFalse();
        assertThat(byKim.input().request()).isNotEmpty();
        Detail shipped = caseScreen.detail(null, "A1", "kim", Locale.KOREAN).orElseThrow();
        assertThat(shipped.row().readonly()).isTrue();
        assertThat(shipped.changes()).isEmpty();
        assertThat(shipped.improvedByEdit()).isNull();
        assertThat(caseScreen.detail(null, "missing-1", "kim", Locale.KOREAN)).isEmpty();
    }

    @Test
    void theListOfMeasurementsHoldsTheTrialsInOneListNewestFirst() {
        PromptQualityCases.PublishedSet set = cases.publish(null, PROMPT, "kim");
        long first = measured(set, 1, NOW.minusSeconds(400), Set.of());
        trial(2, 1, PromptVersionTrials.DONE, NOW.minusSeconds(300));
        long second = measured(set, 2, NOW.minusSeconds(200), Set.of("A1"));
        trial(2, 1, PromptVersionTrials.CANCELLED, NOW.minusSeconds(100));

        RunsView view = measureScreen.runs(null, 0);

        assertThat(view.total()).isEqualTo(4);
        assertThat(view.rows()).extracting(RunRow::kind).containsExactly("SEALED", "CASES", "SEALED", "CASES");
        assertThat(view.rows().get(1).id()).isEqualTo(second);
        assertThat(view.rows().get(3).id()).isEqualTo(first);
        assertThat(view.rows().get(1).miss().k()).isEqualTo(3);
        assertThat(view.rows().get(3).miss().k()).isZero();
        assertThat(view.rows().get(0).status()).isEqualTo(PromptVersionTrials.CANCELLED);
        assertThat(view.rows().get(2).reference()).isEqualTo("v1.0");
        assertThat(view.rows().get(2).pairs()).isZero();
        assertThat(view.start().caseSets()).extracting(PromptQualityMeasureViews.SetOption::id).containsExactly(set.id());
        assertThat(view.start().used()).isEqualTo("v1.0");
        assertThat(view.start().estimate().cases()).isEqualTo(70);
        assertThat(view.band().model()).isEqualTo("model-a");
        assertThat(view.running()).isEmpty();
        assertThat(measureScreen.runs(null, 1).rows()).isEmpty();
    }

    @Test
    void oneMeasurementShowsItsMetricsByBasisAndGrade() {
        // A case added an hour after the versions were made: one their authors could not see.
        PromptQualityCases.Kept kept = new PromptQualityCases(() -> jdbc, JSON, true, PromptVersionAudit.none(),
                Clock.fixed(NOW.plusSeconds(3600), ZoneOffset.UTC), null, null).copy(null, PROMPT, "A1", null,
                answer(Set.of(QualityAction.BLOCK), "later"), QualityCaseGrade.ORDINARY, "lee");
        cases.confirm(null, PROMPT, kept.key(), "kim");
        PromptQualityCases.PublishedSet set = cases.publish(null, PROMPT, "kim");
        long id = measured(set, 2, NOW.minusSeconds(60), Set.of("A1"));

        RunView run = measureScreen.run(null, id).orElseThrow();

        assertThat(run.version()).isEqualTo("v2.0");
        assertThat(run.answers()).isEqualTo(213);
        assertThat(run.firstAnswer().headline()).extracting(Metric::key)
                .containsExactly("MISS", "FALSE_STOP", "ACTION_HIT", "CITATION_ACCURACY");
        assertThat(run.firstAnswer().headline().get(0).k()).isEqualTo(3);
        // Quality plan 3.3 (supplement P-8): with three runs, the cases missed in at least one run, beside the rate.
        Metric miss = run.firstAnswer().headline().get(0);
        assertThat(miss.anyCases()).isEqualTo(1);
        assertThat(miss.anyOf()).isNotNull().satisfies(count -> assertThat(count * 3L).isEqualTo(miss.n()));
        assertThat(run.firstAnswer().grades().get(0).metrics()).filteredOn(metric -> metric.key().equals("CONSISTENCY")
                || metric.key().equals("TIME")).extracting(Metric::anyCases).containsOnlyNulls();
        assertThat(PromptQualityMeasureScreen.metric(QualityMetric.MISS, new QualityRate(1, 3, 3, 1, 3), 1)
                .anyCases()).as("one run has no 'at least once'").isNull();
        assertThat(run.firstAnswer().grades()).extracting(GradeMetrics::key)
                .startsWith("ALL", "CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC");
        assertThat(run.firstAnswer().grades().get(0).metrics()).hasSize(11);
        assertThat(run.firstAnswer().grades()).filteredOn(grade -> grade.key().equals("NORMAL"))
                .extracting(GradeMetrics::metrics).containsOnlyNulls();
        assertThat(run.firstAnswer().split().contexa().cases()).isEqualTo(70);
        assertThat(run.firstAnswer().split().ours().cases()).isEqualTo(1);
        assertThat(run.firstAnswer().later().cases()).isEqualTo(1);
        assertThat(run.picks()).extracting(PromptQualityMeasureViews.Pick::id).containsExactly(id);
        assertThat(measureScreen.run(null, null)).map(RunView::id).contains(id);
        assertThat(measureScreen.run(null, id + 99)).isEmpty();
    }

    @Test
    void twoVersionsAreComparedAsTheGateComparesThem() {
        PromptQualityCases.PublishedSet set = cases.publish(null, PROMPT, "kim");
        long current = measured(set, 1, NOW.minusSeconds(300), Set.of());
        long candidate = measured(set, 2, NOW.minusSeconds(100), Set.of("A1", "S04"));

        CompareView view = measureScreen.compare(null, null, null, null, null);

        assertThat(view.candidate()).isEqualTo(2);
        assertThat(view.current()).isEqualTo(1);
        assertThat(view.comparable()).isTrue();
        assertThat(view.state()).isEqualTo("MEASURED");
        assertThat(view.currentSide().measureId()).isEqualTo(current);
        assertThat(view.candidateSide().measureId()).isEqualTo(candidate);
        assertThat(view.same().repeats()).isEqualTo(3);
        assertThat(view.splits().newMiss()).isEqualTo(2);
        assertThat(view.rows()).extracting(SplitRow::key).containsExactlyInAnyOrder("A1", "S04");
        assertThat(view.rows()).allSatisfy(row -> {
            assertThat(row.split()).isEqualTo("NEW_MISS");
            assertThat(row.currentActions()).containsExactly("BLOCK");
            assertThat(row.candidateActions()).containsExactly("ALLOW");
        });
        assertThat(view.metrics()).filteredOn(row -> row.key().equals("MISS"))
                .allSatisfy(row -> assertThat(row.candidate().k()).isEqualTo(6));
        assertThat(view.grades()).extracting(PromptQualityMeasureViews.GradeCompare::key)
                .startsWith("CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC");
        assertThat(view.grades()).filteredOn(grade -> grade.key().equals("NORMAL"))
                .allSatisfy(grade -> assertThat(grade.compared()).isFalse());
        assertThat(view.grades().stream().mapToInt(PromptQualityMeasureViews.GradeCompare::newMisses).sum())
                .isEqualTo(2);

        CaseAnswers answers = measureScreen.caseAnswers(null, 2, 1, null, null, "A1").orElseThrow();
        assertThat(answers.current().actions()).containsExactly("BLOCK", "BLOCK", "BLOCK");
        assertThat(answers.candidate().actions()).containsExactly("ALLOW", "ALLOW", "ALLOW");
        assertThat(answers.candidate().findings()).extracting(PromptQualityMeasureViews.Finding::code,
                PromptQualityMeasureViews.Finding::fact).containsExactly(tuple(
                "NO_COVERING_RECORD", "F5"));
        assertThat(answers.current().findings()).isEmpty();
        assertThat(measureScreen.caseAnswers(null, 2, 1, null, null, "nothing-1")).isEmpty();
        CompareView none = measureScreen.compare(null, 1, 2, null, null);
        assertThat(none.comparable()).isTrue();
        assertThat(none.splits().newCatch()).isEqualTo(2);
    }

    /**
     * Two measurements by their ids, as the scheduled measurement compares a version measured twice: compared the
     * same way when taken the same way (they win over the versions given with them), else why not.
     */
    @Test
    void twoMeasurementsAreComparedWhenTakenTheSameWayElseWhyNot() {
        PromptQualityCases.PublishedSet set = cases.publish(null, PROMPT, "kim");
        long earlier = measured(set, 1, NOW.minusSeconds(300), Set.of());
        long later = measured(set, 1, NOW.minusSeconds(100), Set.of("A1"));

        CompareView view = measureScreen.compare(null, 2, 2, later, earlier);

        assertThat(view.comparable()).isTrue();
        assertThat(view.candidateMeasure()).isEqualTo(later);
        assertThat(view.referenceMeasure()).isEqualTo(earlier);
        assertThat(view.candidate()).isEqualTo(1);
        assertThat(view.current()).isEqualTo(1);
        assertThat(view.candidateSide().measureId()).isEqualTo(later);
        assertThat(view.currentSide().measureId()).isEqualTo(earlier);
        assertThat(view.splits().newMiss()).isEqualTo(1);
        assertThat(view.rows()).extracting(SplitRow::key).containsExactly("A1");
        assertThat(view.grades().stream().mapToInt(PromptQualityMeasureViews.GradeCompare::newMisses).sum())
                .isEqualTo(1);
        assertThat(view.picks()).extracting(PromptQualityMeasureViews.Pick::id).containsExactly(later, earlier);
        CaseAnswers answers = measureScreen.caseAnswers(null, null, null, later, earlier, "A1").orElseThrow();
        assertThat(answers.candidate().measureId()).isEqualTo(later);
        assertThat(answers.candidate().actions()).containsExactly("ALLOW", "ALLOW", "ALLOW");
        assertThat(answers.current().actions()).containsExactly("BLOCK", "BLOCK", "BLOCK");

        jdbc.update("update ctxa_prompt_version_measure set repeats = 1 where id = ?", earlier);
        CompareView different = measureScreen.compare(null, null, null, later, earlier);
        assertThat(different.comparable()).isFalse();
        assertThat(different.state()).isEqualTo(PromptQualityMeasureScreen.INCOMPARABLE);
        assertThat(different.differences()).containsExactly(PromptQualityMeasureScreen.REPEATS);
        CompareView missing = measureScreen.compare(null, null, null, later, later + 99);
        assertThat(missing.state()).isEqualTo(PromptQualityMeasureScreen.NOT_FOUND);
        assertThat(missing.sides()).containsExactly("CURRENT");
    }
}
