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
package io.contexa.contexaiam.admin.promptquality.measure;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionCitationCheck;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurement;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityScore;
import io.contexa.contexacore.std.llm.gate.ModelCallTimer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayInputs;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseSealedForm;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Quality plan 3.3, 3.9, 9 on a database with the schema of a new installation, the replay stood in for: a version is
 * measured on a published case set, each case run as many times as asked, and scored on the first answer and on the
 * final action the closing rules give; the measurement waits in the line of the trials and its calls wait behind the
 * decisions; an answer kept for the same case, version, model setting and run is used again; a measurement a server
 * left is resumed case by case and run by run; two servers share one lock and a cancellation; a busy model server is
 * asked again and then left out as incomplete; the model calls are estimated before the start and limited.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityMeasurementsPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String SCOPE = PromptVersionService.PLATFORM_SCOPE;
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final Map<String, String> SETTINGS = Map.of("layer1.model", "stand-in-model");
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;
    private static QualityCaseSet all;

    private final List<PromptQualityMeasurements> opened = new CopyOnWriteArrayList<>();
    private final List<PromptQualityRunLine> lines = new CopyOnWriteArrayList<>();
    private final List<String> asked = new CopyOnWriteArrayList<>();
    /** The scope each replay read its version in and the time zone it was drawn in. */
    private final List<String> askedWith = new CopyOnWriteArrayList<>();
    private final List<Boolean> behind = new CopyOnWriteArrayList<>();
    private PromptVersionService versions;

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
        all = QualityCaseSetReader.contexaDefault();
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    @BeforeEach
    void theProductVersions() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_case_cause, ctxa_prompt_version_measure_prompt,"
                + " ctxa_prompt_version_measure_answer, ctxa_prompt_version_measure, ctxa_prompt_version_case_set_member,"
                + " ctxa_prompt_version_case_set, ctxa_prompt_version_case_change, ctxa_prompt_version_case,"
                + " ctxa_prompt_version_part, ctxa_prompt_version, ctxa_shedlock CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), Map.of(),
                PromptVersionAudit.none(), Clock.systemUTC());
        versions.registerProducts(null);
        versions.create(null, """
                prompt: cortex.security-decision
                basedOn: v1.0
                title: Finance closing
                system:
                  - key: how-to-judge
                    text: |
                      1. Weigh the duty roster first.
                """, PromptVersionRecord.SCREEN, null, "admin", null);
    }

    @AfterEach
    void closeAll() {
        opened.forEach(PromptQualityMeasurements::close);
        lines.forEach(PromptQualityRunLine::close);
    }

    // ----- fixtures -----

    private static PromptQualityCases cases(List<QualityCase> shipped) {
        QualityCaseSet set = new QualityCaseSet(all.name(), shipped);
        return new PromptQualityCases(() -> jdbc, JSON, false, PromptVersionAudit.none(), Clock.systemUTC(), null,
                () -> set);
    }

    private static PromptQualityMeasurements.Settings settings(int concurrency, int retries, int callLimit) {
        return new PromptQualityMeasurements.Settings(3, concurrency, retries, Duration.ZERO, callLimit,
                Duration.ofMillis(200));
    }

    private static QualityMeasureLock sharedLock() {
        return QualityMeasureLock.shedLock(new JdbcTemplateLockProvider(jdbc, "ctxa_shedlock"),
                PromptQualityMeasurements.LOCK_NAME, Clock.systemUTC());
    }

    private PromptQualityMeasurements measurements(PromptQualityCases cases, PromptQualityMeasurements.Replayer replayer,
                                                   PromptQualityMeasurements.Settings settings, QualityMeasureLock lock,
                                                   String server, Map<String, String> modelSettings,
                                                   PromptQualityRunLine line) {
        PromptQualityMeasurements measurements = new PromptQualityMeasurements(() -> jdbc, versions, cases, replayer,
                line, lock, () -> modelSettings, () -> QualityClosingRules.DEFAULTS, settings, JSON,
                Clock.systemUTC(), server);
        opened.add(measurements);
        return measurements;
    }

    private PromptQualityRunLine line() {
        PromptQualityRunLine line = new PromptQualityRunLine();
        lines.add(line);
        return line;
    }

    private static String keyOf(SealedEvidencePackage given) {
        return given.getPackageId().substring(QualityCaseSealedForm.PACKAGE_ID_PREFIX.length());
    }

    private static boolean defers(String key) {
        return key.endsWith("T");
    }

    /** The stand-in's answer to a case: stop the ones to stop (deferring some), allow the others. */
    private static String standInAction(QualityCase item) {
        return !item.shouldStop() ? "ALLOW" : defers(item.key()) ? "ESCALATE" : "BLOCK";
    }

    private static SealedDecisionReplayService.ModelCall call() {
        return new SealedDecisionReplayService.ModelCall(6500L, 20L, 90000L, false);
    }

    /** An answer of the replay: three facts cited, all on a line of the prompt and one named by the check. */
    static SealedDecisionReplayService.Result answered(SealedEvidencePackage given, String action,
                                                       SealedDecisionReplayService.Outcome outcome,
                                                       List<SealedDecisionReplayService.SecondPass> second) {
        return new SealedDecisionReplayService.Result(given.getCorrelationId(), "replay-1", given.getPackageId(),
                "v1.0", action, "stand-in", List.of(), null, null,
                Map.of("runtimeModelId", "stand-in-model", "actualCompletionTokens", 120), 7000L, null, second,
                outcome, action, "the system prompt", "the user prompt of " + given.getPackageId(),
                new SecurityDecisionCitationCheck(SecurityDecisionCitationCheck.State.CHECKED, 3, 3, 1, 0, true,
                        List.of()), List.of(call()));
    }

    static SealedDecisionReplayService.Result failed(SealedEvidencePackage given,
                                                     SealedDecisionReplayService.Outcome outcome, String failure) {
        return new SealedDecisionReplayService.Result(given.getCorrelationId(), "replay-1", given.getPackageId(),
                "v1.0", null, null, List.of(), null, null, Map.of(), 100L, failure, List.of(), outcome, null, null,
                null, null, List.of());
    }

    static SealedDecisionReplayService.SecondPass secondPass(String action, SealedDecisionReplayService.Outcome outcome) {
        return new SealedDecisionReplayService.SecondPass(null, action, "second", List.of(), null, null,
                Map.of("runtimeModelId", "stand-in-second-model"), 5000L, null, outcome, action, null, null, null,
                List.of(call()));
    }

    /** The stand-in of the replay, asked with the answers the function gives each case. */
    private PromptQualityMeasurements.Replayer standIn(Function<SealedEvidencePackage, SealedDecisionReplayService.Result> answer) {
        return (actor, given, format, version, user, organization, scope, timeZone) -> {
            ModelCallTimer timer = ModelCallTimer.current();
            behind.add(timer != null && timer.behindDecisions());
            asked.add(keyOf(given) + "|" + version + "|" + format);
            askedWith.add(scope + "|" + timeZone);
            return answer.apply(given);
        };
    }

    private PromptQualityMeasurements.Replayer standInOf(List<QualityCase> shipped) {
        Map<String, QualityCase> byKey = new TreeMap<>();
        shipped.forEach(item -> byKey.put(item.key(), item));
        return standIn(given -> {
            String action = standInAction(byKey.get(keyOf(given)));
            return answered(given, action, SealedDecisionReplayService.Outcome.ANSWERED,
                    "ESCALATE".equals(action) ? List.of(secondPass("CHALLENGE",
                            SealedDecisionReplayService.Outcome.ANSWERED)) : List.of());
        });
    }

    private static PromptQualityMeasurements.Measure await(PromptQualityMeasurements measurements, long id,
                                                           String... statuses) throws InterruptedException {
        Set<String> wanted = Set.of(statuses);
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (System.nanoTime() < until) {
            PromptQualityMeasurements.Measure measure = measurements.find(id).orElseThrow();
            if (wanted.contains(measure.status())) {
                return measure;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("Measurement " + id + " is " + measurements.find(id).orElseThrow().status());
    }

    private static int count(String sql, Object... arguments) {
        Integer count = jdbc.queryForObject(sql, Integer.class, arguments);
        return count != null ? count : 0;
    }

    // ----- the tests -----

    /** Quality plan 5 stage 3: one version measured on the default set, and its metrics with their ranges. */
    @Test
    void theDefaultSetIsMeasuredRunByRunAndScoredOnBothBases() throws Exception {
        PromptQualityCases cases = cases(all.cases());
        PromptQualityCases.PublishedSet set = cases.publish(SCOPE, PROMPT, "admin");
        PromptQualityMeasurements measurements = measurements(cases, standInOf(all.cases()), settings(2, 2, 3000),
                sharedLock(), "server-a", SETTINGS, line());
        long stopping = all.cases().stream().filter(QualityCase::shouldStop).count();
        long deferring = all.cases().stream().filter(item -> item.shouldStop() && defers(item.key())).count();

        long id = measurements.start(SCOPE, PROMPT, 1, null, null, "admin");
        PromptQualityMeasurements.Measure measure = await(measurements, id, PromptQualityMeasurements.DONE);

        assertThat(measure.answered()).isEqualTo(210);
        assertThat(measure.repeats()).isEqualTo(3);
        assertThat(measure.caseSetVersion()).isEqualTo(set.version());
        assertThat(measure.modelCalls()).isEqualTo(210 + (int) deferring * 3);
        assertThat(measure.runnerId()).isEqualTo("server-a");
        assertThat(measure.closingRules()).contains(QualityClosingRules.OVERLOAD_PROTECTION_LEFT_OUT);
        assertThat(measure.modelSetting()).isEqualTo("settings=" + QualityModelSetting.hash(SETTINGS)
                + ";models=stand-in-model,stand-in-second-model");
        assertThat(behind).hasSize(210).containsOnly(true);
        assertThat(asked).allMatch(entry -> entry.endsWith("|v1.0|" + SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION));

        PromptQualityMeasurements.Result result = measurements.result(id).orElseThrow();
        assertThat(result.missingCases()).isEmpty();
        QualityScore first = result.firstAnswer();
        assertThat(first.scoredAnswers()).isEqualTo(210);
        assertThat(first.rate(QualityMetric.MISS).events()).isZero();
        assertThat(first.rate(QualityMetric.MISS).trials()).isEqualTo(stopping * 3);
        assertThat(first.rate(QualityMetric.MISS).lower()).isZero();
        assertThat(first.rate(QualityMetric.MISS).upper()).isBetween(0.0, 0.5);
        assertThat(first.rate(QualityMetric.FALSE_STOP).events()).isZero();
        assertThat(first.rate(QualityMetric.DEFERRAL).events()).isEqualTo(deferring * 3);
        assertThat(first.rate(QualityMetric.CONSISTENCY).value()).isEqualTo(1.0);
        assertThat(first.rate(QualityMetric.CITATION_ACCURACY).events()).isEqualTo(420);
        assertThat(first.rate(QualityMetric.CITATION_ACCURACY).trials()).isEqualTo(630);
        // On the final action the second pass ended every ESCALATE.
        QualityScore last = result.finalAction();
        assertThat(last.scoredAnswers()).isEqualTo(210);
        assertThat(count("select count(*) from ctxa_prompt_version_measure_answer where measure_id = ? and"
                + " first_action = 'ESCALATE' and final_action = 'CHALLENGE' and second_pass_action = 'CHALLENGE'",
                id)).isEqualTo((int) deferring * 3);
        assertThat(count("select count(*) from ctxa_prompt_version_measure_answer where measure_id = ? and"
                + " final_action = 'ESCALATE'", id)).isZero();
        // The measurement is one the scoring compares with another taken the same way.
        QualityMeasurement measurement = result.measurement();
        assertThat(measurement.answers()).hasSize(210);
        assertThat(measurement.comparableWith(new QualityMeasurement("v2.0", measure.modelSetting(), set.version(), 3,
                List.of()))).isTrue();
        // Each answer keeps its prompts by their hash, the prompts once each; its citations and its calls.
        assertThat(count("select count(*) from ctxa_prompt_version_measure_prompt")).isEqualTo(71);
        assertThat(count("select count(*) from ctxa_prompt_version_measure_answer where measure_id = ? and"
                + " (system_prompt_hash is null or user_prompt_hash is null)", id)).isZero();
        assertThat(jdbc.queryForObject("select model_calls from ctxa_prompt_version_measure_answer where measure_id = ?"
                + " and second_pass_action is not null limit 1", String.class, id))
                .contains("\"pass\":1").contains("\"pass\":2").contains("\"callMs\":6500");
        assertThat(count("select count(*) from ctxa_prompt_version_measure_answer where measure_id = ? and"
                + " cited_facts = 3 and present_facts = 3 and flagged_facts = 1 and accurate_cited_facts = 2 and"
                + " citation_state = 'CHECKED' and model_action is not null and answered_model = 'stand-in-model'",
                id)).isEqualTo(210);
    }

    /** Quality plan 3.3: the measurement waits in the line the trials wait in, one job after the other. */
    @Test
    void aMeasurementWaitsInTheLineOfTheTrials() throws Exception {
        List<QualityCase> three = all.cases().subList(0, 3);
        PromptQualityCases cases = cases(three);
        cases.publish(SCOPE, PROMPT, "admin");
        PromptQualityRunLine line = line();
        CountDownLatch trialRuns = new CountDownLatch(1);
        line.executor().execute(() -> {
            try {
                trialRuns.await(10, TimeUnit.SECONDS);
            }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        });
        PromptQualityMeasurements measurements = measurements(cases, standInOf(three), settings(1, 0, 0),
                QualityMeasureLock.local(), "server-a", SETTINGS, line);

        long id = measurements.start(SCOPE, PROMPT, 1, null, 1, "admin");
        Thread.sleep(300);
        assertThat(measurements.find(id).orElseThrow().status()).isEqualTo(PromptQualityMeasurements.QUEUED);
        assertThat(asked).isEmpty();

        trialRuns.countDown();
        assertThat(await(measurements, id, PromptQualityMeasurements.DONE).answered()).isEqualTo(3);
    }

    @Test
    void anAnswerKeptForTheSameCaseVersionSettingAndRunIsUsedAgain() throws Exception {
        List<QualityCase> three = all.cases().subList(0, 3);
        PromptQualityCases cases = cases(three);
        cases.publish(SCOPE, PROMPT, "admin");
        PromptQualityMeasurements measurements = measurements(cases, standInOf(three), settings(1, 2, 0),
                QualityMeasureLock.local(), "server-a", SETTINGS, line());
        await(measurements, measurements.start(SCOPE, PROMPT, 1, null, 2, "admin"), PromptQualityMeasurements.DONE);
        assertThat(asked).hasSize(6);

        PromptQualityMeasurements.Estimate estimate = measurements.estimate(SCOPE, PROMPT, 1, null, 3);
        assertThat(estimate.answers()).isEqualTo(9);
        assertThat(estimate.reusable()).isEqualTo(6);
        assertThat(estimate.replays()).isEqualTo(3);
        long again = measurements.start(SCOPE, PROMPT, 1, null, 3, "admin");
        assertThat(await(measurements, again, PromptQualityMeasurements.DONE).answered()).isEqualTo(9);
        assertThat(asked).hasSize(9);
        assertThat(count("select count(*) from ctxa_prompt_version_measure_answer where measure_id = ? and"
                + " reused_from_answer_id is not null", again)).isEqualTo(6);
        assertThat(measurements.find(again).orElseThrow().reusableAnswers()).isEqualTo(6);

        // Another model setting, or another version, answers again.
        PromptQualityMeasurements otherSetting = measurements(cases, standInOf(three), settings(1, 2, 0),
                QualityMeasureLock.local(), "server-a", Map.of("layer1.model", "another-model"), line());
        assertThat(otherSetting.estimate(SCOPE, PROMPT, 1, null, 3).reusable()).isZero();
    }

    /**
     * Quality P32: a measurement taken anew uses no kept answer, so the model is asked for every answer and the
     * estimate counts every one as a replay; it is marked, and with the first measurement of the version, whose answers
     * are its own too, it gives the quality gate its noise, which a measurement that used the kept answers again does
     * not. Quality plan 3.2: each replay reads the version of the measurement's scope and is drawn in the time zone
     * the case fixes.
     */
    @Test
    void aMeasurementTakenAnewAsksForEveryAnswerAndGivesTheGateItsNoise() throws Exception {
        List<QualityCase> three = all.cases().subList(0, 3);
        PromptQualityCases cases = cases(three);
        cases.publish(SCOPE, PROMPT, "admin");
        PromptQualityMeasurements measurements = measurements(cases, standInOf(three), settings(1, 2, 0),
                QualityMeasureLock.local(), "server-a", SETTINGS, line());
        long first = measurements.start(SCOPE, PROMPT, 1, null, 2, "admin");
        await(measurements, first, PromptQualityMeasurements.DONE);
        long reused = measurements.start(SCOPE, PROMPT, 1, null, 2, "admin");
        await(measurements, reused, PromptQualityMeasurements.DONE);
        assertThat(asked).hasSize(6);
        MeasuredQualityGateSource gate = new MeasuredQualityGateSource(() -> jdbc, versions, cases,
                () -> measurements, null);
        assertThat(gate.read(SCOPE, PROMPT, "v2.0", "v1.0").input().noise().widths()).isEmpty();

        PromptQualityMeasurements.Estimate estimate = measurements.estimate(SCOPE, PROMPT, 1, null, 2, true);
        assertThat(estimate.answers()).isEqualTo(6);
        assertThat(estimate.reusable()).isZero();
        assertThat(estimate.replays()).isEqualTo(6);
        assertThat(estimate.minimumCalls()).isEqualTo(6);
        assertThat(measurements.estimate(SCOPE, PROMPT, 1, null, 2).reusable()).isEqualTo(6);
        long anew = measurements.start(SCOPE, PROMPT, 1, null, 2, true, "admin");
        PromptQualityMeasurements.Measure measure = await(measurements, anew, PromptQualityMeasurements.DONE);

        assertThat(measure.anew()).isTrue();
        assertThat(measure.reusableAnswers()).isZero();
        assertThat(measure.answered()).isEqualTo(6);
        assertThat(asked).hasSize(12);
        assertThat(count("select count(*) from ctxa_prompt_version_measure_answer where measure_id = ? and"
                + " reused_from_answer_id is not null", anew)).isZero();
        assertThat(measurements.find(first).orElseThrow().anew()).isFalse();
        assertThat(measurements.find(reused).orElseThrow().anew()).isFalse();
        assertThat(gate.read(SCOPE, PROMPT, "v2.0", "v1.0").input().noise().width(QualityMetric.MISS)).isPresent();
        assertThat(askedWith).hasSize(12).containsOnly(SCOPE + "|UTC");
    }

    /** Quality plan 3.3, 6: a measurement a stopped server left is resumed where it stopped, by another server. */
    @Test
    void aMeasurementAServerLeftIsResumedCaseByCaseAndRunByRun() throws Exception {
        List<QualityCase> three = all.cases().subList(0, 3);
        PromptQualityCases cases = cases(three);
        cases.publish(SCOPE, PROMPT, "admin");
        PromptQualityRunLine stopped = new PromptQualityRunLine();
        stopped.close();
        PromptQualityMeasurements gone = measurements(cases, standInOf(three), settings(1, 0, 0), sharedLock(),
                "server-gone", SETTINGS, stopped);
        long left = gone.start(SCOPE, PROMPT, 1, null, 2, "admin");
        long alive = gone.start(SCOPE, PROMPT, 2, null, 2, "admin");
        // The server that stopped had taken two answers of the first; the second runs on a server that is alive.
        leftBy(left, "server-gone", Instant.now().minus(Duration.ofMinutes(5)));
        keptAnswer(left, three.get(0), 1);
        keptAnswer(left, three.get(1), 1);
        leftBy(alive, "server-alive", Instant.now().plus(Duration.ofMinutes(5)));

        PromptQualityMeasurements resumer = measurements(cases, standInOf(three), settings(1, 0, 0), sharedLock(),
                "server-b", SETTINGS, line());
        resumer.drain();

        PromptQualityMeasurements.Measure resumed = resumer.find(left).orElseThrow();
        assertThat(resumed.status()).isEqualTo(PromptQualityMeasurements.DONE);
        assertThat(resumed.runnerId()).isEqualTo("server-b");
        assertThat(resumed.answered()).isEqualTo(6);
        // Only the answers it did not have are asked: one run of the first two cases, both runs of the third.
        assertThat(asked).hasSize(4);
        assertThat(asked.stream().filter(entry -> entry.startsWith(three.get(0).key() + "|"))).hasSize(1);
        assertThat(asked.stream().filter(entry -> entry.startsWith(three.get(1).key() + "|"))).hasSize(1);
        assertThat(asked.stream().filter(entry -> entry.startsWith(three.get(2).key() + "|"))).hasSize(2);
        assertThat(count("select count(*) from ctxa_prompt_version_measure_answer where measure_id = ? and"
                + " case_key = ? and run_number = 2", left, three.get(0).key())).isEqualTo(1);
        PromptQualityMeasurements.Measure untouched = resumer.find(alive).orElseThrow();
        assertThat(untouched.status()).isEqualTo(PromptQualityMeasurements.RUNNING);
        assertThat(untouched.runnerId()).isEqualTo("server-alive");
        assertThat(untouched.answered()).isZero();
    }

    /**
     * Quality plan 3.5, 3.9 (supplement U1): what follows a measurement once done is told to every listener added, in
     * order; one that fails leaves the measurement done and the others told.
     */
    @Test
    void everyListenerIsToldOnceAMeasurementIsDone() throws Exception {
        List<QualityCase> three = all.cases().subList(0, 3);
        PromptQualityCases cases = cases(three);
        cases.publish(SCOPE, PROMPT, "admin");
        PromptQualityMeasurements measurements = measurements(cases, standInOf(three), settings(1, 0, 0),
                QualityMeasureLock.local(), "server-a", SETTINGS, line());
        List<String> told = new CopyOnWriteArrayList<>();
        measurements.whenDone(done -> {
            told.add("causes " + done);
            throw new IllegalStateException("a listener that fails");
        });
        measurements.whenDone(null);
        measurements.whenDone(done -> told.add("ledger " + done));

        long id = measurements.start(SCOPE, PROMPT, 1, null, 1, "admin");
        assertThat(await(measurements, id, PromptQualityMeasurements.DONE).answered()).isEqualTo(3);
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (told.size() < 2 && System.nanoTime() < until) {
            Thread.sleep(20);
        }

        assertThat(told).containsExactly("causes " + id, "ledger " + id);
        assertThat(measurements.find(id).orElseThrow().status()).isEqualTo(PromptQualityMeasurements.DONE);
    }

    /** Quality plan 9, 6: one server at a time runs measurements, and a cancellation on another reaches it. */
    @Test
    void twoServersShareOneLockAndACancellationReachesTheServerThatRuns() throws Exception {
        List<QualityCase> three = all.cases().subList(0, 3);
        PromptQualityCases cases = cases(three);
        cases.publish(SCOPE, PROMPT, "admin");
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger askedOfA = new AtomicInteger();
        PromptQualityMeasurements.Replayer slow = standIn(given -> {
            askedOfA.incrementAndGet();
            entered.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
                Thread.sleep(150);
            }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return answered(given, "BLOCK", SealedDecisionReplayService.Outcome.ANSWERED, List.of());
        });
        AtomicInteger askedOfB = new AtomicInteger();
        PromptQualityMeasurements.Replayer counting = (actor, given, format, version, user, organization, scope,
                                                       timeZone) -> {
            askedOfB.incrementAndGet();
            return answered(given, "BLOCK", SealedDecisionReplayService.Outcome.ANSWERED, List.of());
        };
        PromptQualityMeasurements serverA = measurements(cases, slow, settings(1, 0, 0), sharedLock(), "server-a",
                SETTINGS, line());
        PromptQualityMeasurements serverB = measurements(cases, counting, settings(1, 0, 0), sharedLock(), "server-b",
                SETTINGS, line());

        long running = serverA.start(SCOPE, PROMPT, 1, null, 3, "admin-a");
        assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();
        // B cannot take the lock while A runs: what B queues waits, and B runs nothing.
        long queued = serverB.start(SCOPE, PROMPT, 2, null, 1, "admin-b");
        serverB.drain();
        assertThat(askedOfB).hasValue(0);
        assertThat(serverB.find(queued).orElseThrow().status()).isEqualTo(PromptQualityMeasurements.QUEUED);

        assertThat(serverB.cancel(running, "admin-b")).isTrue();
        release.countDown();
        PromptQualityMeasurements.Measure cancelled = await(serverA, running, PromptQualityMeasurements.CANCELLED);
        Thread.sleep(800);
        int answers = serverA.find(running).orElseThrow().answered();
        assertThat(answers).isLessThan(9);
        assertThat(cancelled.status()).isEqualTo(PromptQualityMeasurements.CANCELLED);
        assertThat(count("select count(*) from ctxa_prompt_version_measure where id = ? and cancelled_by = 'admin-b'",
                running)).isEqualTo(1);
        // The server holding the lock goes on with what waits; then the lock is free for B.
        PromptQualityMeasurements.Measure next = await(serverA, queued, PromptQualityMeasurements.DONE);
        assertThat(next.runnerId()).isEqualTo("server-a");
        assertThat(serverA.find(running).orElseThrow().answered()).isEqualTo(answers);
        assertThat(serverA.cancel(running, "admin-a")).isFalse();
    }

    @Test
    void aBusyModelServerIsAskedAgainAndThenLeftOutAsIncomplete() throws Exception {
        List<QualityCase> five = all.cases().subList(0, 5);
        PromptQualityCases cases = cases(five);
        cases.publish(SCOPE, PROMPT, "admin");
        Map<String, AtomicInteger> attempts = new ConcurrentHashMap<>();
        List<String> keys = five.stream().map(QualityCase::key).toList();
        PromptQualityMeasurements measurements = measurements(cases, standIn(given -> {
            String key = keyOf(given);
            int attempt = attempts.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
            int index = keys.indexOf(key);
            return switch (index) {
                case 0 -> failed(given, SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE,
                        "ModelServerBusyException: busy");
                case 1 -> attempt == 1 ? failed(given, SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE,
                        "TimeoutException: no answer") : answered(given, "BLOCK",
                        SealedDecisionReplayService.Outcome.ANSWERED, List.of());
                case 2 -> failed(given, SealedDecisionReplayService.Outcome.CONTEXT_MISSING,
                        "SealedReplayContextMissingException: gone");
                case 3 -> answered(given, "CHALLENGE", SealedDecisionReplayService.Outcome.MODEL_ANSWER_UNUSABLE,
                        List.of());
                default -> answered(given, "ESCALATE", SealedDecisionReplayService.Outcome.ANSWERED,
                        List.of(secondPass(null, attempt == 1 ? SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE
                                : SealedDecisionReplayService.Outcome.ANSWERED)));
            };
        }), settings(1, 2, 0), QualityMeasureLock.local(), "server-a", SETTINGS, line());

        long id = measurements.start(SCOPE, PROMPT, 1, null, 1, "admin");
        await(measurements, id, PromptQualityMeasurements.DONE);

        assertThat(attempts.get(keys.get(0))).hasValue(3);
        assertThat(attempts.get(keys.get(1))).hasValue(2);
        assertThat(attempts.get(keys.get(2))).hasValue(1);
        assertThat(attempts.get(keys.get(3))).hasValue(1);
        assertThat(attempts.get(keys.get(4))).hasValue(2);
        assertThat(jdbc.queryForObject("select failure_reason from ctxa_prompt_version_measure_answer where"
                + " measure_id = ? and case_key = ?", String.class, id, keys.get(0)))
                .startsWith("INFRASTRUCTURE_FAILURE: ModelServerBusyException");
        assertThat(jdbc.queryForObject("select failure_reason from ctxa_prompt_version_measure_answer where"
                + " measure_id = ? and case_key = ?", String.class, id, keys.get(2))).startsWith("CONTEXT_MISSING");
        assertThat(count("select count(*) from ctxa_prompt_version_measure_answer where measure_id = ? and"
                + " measurement_failed", id)).isEqualTo(2);
        assertThat(count("select count(*) from ctxa_prompt_version_measure_answer where measure_id = ? and"
                + " case_key = ? and decided_without_model and not measurement_failed", id, keys.get(3))).isEqualTo(1);
        // An unusable second-pass action is CHALLENGE on the final basis.
        assertThat(jdbc.queryForObject("select final_action from ctxa_prompt_version_measure_answer where"
                + " measure_id = ? and case_key = ?", String.class, id, keys.get(4))).isEqualTo("CHALLENGE");

        QualityScore first = measurements.result(id).orElseThrow().firstAnswer();
        assertThat(first.answers()).isEqualTo(5);
        assertThat(first.incompleteAnswers()).isEqualTo(2);
        assertThat(first.rate(QualityMetric.MODEL_LESS).events()).isEqualTo(1);
        assertThat(first.rate(QualityMetric.MODEL_LESS).trials()).isEqualTo(3);
    }

    @Test
    void theModelCallsAreEstimatedBeforeTheStartAndLimited() throws Exception {
        List<QualityCase> three = all.cases().subList(0, 3);
        PromptQualityCases cases = cases(three);
        // No case set is published yet.
        PromptQualityMeasurements unpublished = measurements(cases, standInOf(three), settings(1, 2, 5),
                QualityMeasureLock.local(), "server-a", SETTINGS, line());
        refused(() -> unpublished.start(SCOPE, PROMPT, 1, null, 3, "admin"),
                PromptQualityMeasurements.Refusal.NO_CASE_SET);
        cases.publish(SCOPE, PROMPT, "admin");

        PromptQualityMeasurements.Estimate estimate = unpublished.estimate(SCOPE, PROMPT, 1, null, 3);
        assertThat(estimate.answers()).isEqualTo(9);
        assertThat(estimate.minimumCalls()).isEqualTo(9);
        assertThat(estimate.maximumCalls()).isEqualTo(9 * 4 * 3);
        assertThat(estimate.withinLimit()).isFalse();
        refused(() -> unpublished.start(SCOPE, PROMPT, 1, null, 3, "admin"), PromptQualityMeasurements.Refusal.CALL_LIMIT);
        refused(() -> unpublished.start(SCOPE, PROMPT, 99, null, 3, "admin"), PromptQualityMeasurements.Refusal.VERSION);
        refused(() -> unpublished.start(SCOPE, PROMPT, 1, null, 0, "admin"), PromptQualityMeasurements.Refusal.REPEATS);
        refused(() -> unpublished.start(SCOPE, "cortex.other-prompt", 1, null, 1, "admin"),
                PromptQualityMeasurements.Refusal.PROMPT);

        // Each answer here takes two calls, the first pass and the second: the limit stops the measurement at it.
        PromptQualityMeasurements limited = measurements(cases, standIn(given -> answered(given, "ESCALATE",
                SealedDecisionReplayService.Outcome.ANSWERED, List.of(secondPass("BLOCK",
                        SealedDecisionReplayService.Outcome.ANSWERED)))), settings(1, 2, 10),
                QualityMeasureLock.local(), "server-a", SETTINGS, line());
        long id = limited.start(SCOPE, PROMPT, 1, null, 3, "admin");
        PromptQualityMeasurements.Measure measure = await(limited, id, PromptQualityMeasurements.FAILED);
        assertThat(measure.failure()).startsWith("CALL_LIMIT_REACHED");
        assertThat(measure.answered()).isEqualTo(5);
        assertThat(measure.modelCalls()).isEqualTo(10);
        assertThat(measure.expectedMinCalls()).isEqualTo(9);
        assertThat(measure.callLimit()).isEqualTo(10);
    }

    @Test
    void theSameMeasurementIsNotStartedTwiceAndAChangedSettingStopsIt() throws Exception {
        List<QualityCase> three = all.cases().subList(0, 3);
        PromptQualityCases cases = cases(three);
        cases.publish(SCOPE, PROMPT, "admin");
        PromptQualityRunLine stopped = new PromptQualityRunLine();
        stopped.close();
        PromptQualityMeasurements queuing = measurements(cases, standInOf(three), settings(1, 0, 0),
                QualityMeasureLock.local(), "server-a", SETTINGS, stopped);
        long id = queuing.start(SCOPE, PROMPT, 1, null, 1, "admin");
        refused(() -> queuing.start(SCOPE, PROMPT, 1, null, 1, "admin"), PromptQualityMeasurements.Refusal.RUNNING);

        // A server set otherwise does not go on with answers of another model setting.
        PromptQualityMeasurements changed = measurements(cases, standInOf(three), settings(1, 0, 0),
                QualityMeasureLock.local(), "server-b", Map.of("layer1.model", "another-model"), line());
        changed.drain();
        PromptQualityMeasurements.Measure measure = changed.find(id).orElseThrow();
        assertThat(measure.status()).isEqualTo(PromptQualityMeasurements.FAILED);
        assertThat(measure.failure()).startsWith("MODEL_SETTINGS_CHANGED");
        assertThat(asked).isEmpty();
    }

    private static void refused(Runnable start, PromptQualityMeasurements.Refusal refusal) {
        assertThatThrownBy(start::run).isInstanceOfSatisfying(PromptQualityMeasurements.RefusedException.class,
                refused -> assertThat(refused.refusal()).isEqualTo(refusal));
    }

    private static void leftBy(long id, String server, Instant heartbeat) {
        jdbc.update("update ctxa_prompt_version_measure set status = 'RUNNING', runner_id = ?, heartbeat_at = ?,"
                + " started_at = ? where id = ?", server, Timestamp.from(heartbeat), Timestamp.from(Instant.now()), id);
    }

    private static void keptAnswer(long id, QualityCase item, int run) {
        Map<String, Object> measure = jdbc.queryForMap("select version_number, version_content_hash, settings_hash"
                + " from ctxa_prompt_version_measure where id = ?", id);
        jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                + " case_content_hash, version_number, version_content_hash, settings_hash, run_number, outcome,"
                + " first_action, final_action, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, 'ANSWERED', 'BLOCK', 'BLOCK',"
                + " ?)", id, SCOPE, item.key(), item.contentHash(), measure.get("version_number"),
                measure.get("version_content_hash"), measure.get("settings_hash"), run, Timestamp.from(Instant.now()));
    }
}
