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
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.components.prompt.quality.QualityRemeasureComparison;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.6 on a database with the schema of a new installation: the version in use is measured again on
 * schedule only for what is new (a case set with new cases, settings that change an answer), a changed model setting
 * is measured once, one server queues each, and a measurement taken again is compared once with the one before.
 * Nothing is replayed: the runners never take the lock of the measurements.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class QualityScheduledMeasurementPostgresTest {

    private static final String SCOPE = PromptVersionService.PLATFORM_SCOPE;
    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Clock CLOCK = Clock.systemUTC();
    private static final Map<String, String> SETTINGS = Map.of("layer1.model", "model-a");
    private static final Map<String, String> OTHER_SETTINGS = Map.of("layer1.model", "model-b");
    private static QualityCaseSet all;
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private final AtomicReference<Map<String, String>> settings = new AtomicReference<>(SETTINGS);
    private final List<PromptQualityMeasurements> opened = new CopyOnWriteArrayList<>();
    private final List<PromptQualityRunLine> lines = new CopyOnWriteArrayList<>();
    private final List<QualityAutoMeasurement> autos = new CopyOnWriteArrayList<>();
    private PromptVersionService versions;
    private PromptQualityCases cases;

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

    /** v1.0 is the product version, v2.0 an organization's version on it, labelled to decide. */
    @BeforeEach
    void aVersionInUse() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_case_cause, ctxa_prompt_version_measure_prompt,"
                + " ctxa_prompt_version_measure_answer, ctxa_prompt_version_measure, ctxa_prompt_version_case_set_member,"
                + " ctxa_prompt_version_case_set, ctxa_prompt_version_case_change, ctxa_prompt_version_case,"
                + " ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_governance_registry, ctxa_shedlock CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), TARGETS,
                PromptVersionAudit.none(), CLOCK);
        versions.registerProducts(null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Payroll\nsystem:\n"
                + "  - key: how-to-judge\n    text: |\n      1. Weigh the payroll roster first.\n",
                PromptVersionRecord.SCREEN, null, "admin", null);
        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'ACTIVE', updated_at = ? where"
                + " prompt_version = 'v2.0'", Timestamp.from(Instant.now()));
        List<QualityCase> some = new ArrayList<>(all.cases().stream().filter(QualityCase::shouldStop).limit(4).toList());
        some.addAll(all.cases().stream().filter(item -> !item.shouldStop()).limit(4).toList());
        QualityCaseSet shipped = new QualityCaseSet(all.name(), some);
        cases = new PromptQualityCases(() -> jdbc, JSON, false, PromptVersionAudit.none(), CLOCK, null, () -> shipped);
    }

    @AfterEach
    void closeAll() {
        autos.forEach(QualityAutoMeasurement::close);
        opened.forEach(PromptQualityMeasurements::close);
        lines.forEach(PromptQualityRunLine::close);
    }

    /**
     * Quality P32: the schedule measures the version in use anew each time, with no kept answer used again, though the
     * version, the case set and the settings were measured already; it starts nothing while a measurement of the
     * version waits, measures on the set published latest, and tries again a measurement it could not finish.
     */
    @Test
    void theScheduleMeasuresAnewAndStartsNothingWhileOneWaits() {
        PromptQualityMeasurements runner = measurements();
        PromptQualityCases.PublishedSet first = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(first, NOW(), "admin", null, QualityScheduledMeasurementPostgresTest::sound);
        QualityScheduledMeasurement scheduled = scheduled(runner, shared());

        scheduled.remeasureOnSchedule();
        scheduled.remeasureOnSchedule();
        List<Map<String, Object>> rows = rows();
        assertThat(rows).as("measured anew once; asked again while it waits, nothing more").hasSize(2);
        assertThat(rows.get(1)).containsEntry("start_reason", "SCHEDULED").containsEntry("status", "QUEUED")
                .containsEntry("measured_anew", true).containsEntry("case_set_id", first.id())
                .containsEntry("planned_answers", 24).containsEntry("reusable_answers", 0)
                .containsEntry("created_by", QualityAutoMeasurement.ACTOR);

        jdbc.update("update ctxa_prompt_version_measure set status = 'DONE' where id = ?", rows.get(1).get("id"));
        QualityCase source = cases.defaultSet().cases().get(0);
        cases.copy(SCOPE, PROMPT, source.key(), null, source.expectation(), source.grade(), "admin");
        PromptQualityCases.PublishedSet second = cases.publish(SCOPE, PROMPT, "admin");
        scheduled.remeasureOnSchedule();
        rows = rows();
        assertThat(rows).as("a measurement done does not stop the schedule").hasSize(3);
        assertThat(rows.get(2)).containsEntry("start_reason", "SCHEDULED").containsEntry("measured_anew", true)
                .containsEntry("case_set_id", second.id()).containsEntry("planned_answers", 27)
                .containsEntry("reusable_answers", 0);

        jdbc.update("update ctxa_prompt_version_measure set status = 'FAILED' where id = ?", rows.get(2).get("id"));
        scheduled.remeasureOnSchedule();
        assertThat(rows()).hasSize(4).last().satisfies(row -> assertThat(row).containsEntry("status", "QUEUED")
                .containsEntry("start_reason", "SCHEDULED").containsEntry("measured_anew", true));
    }

    /**
     * A version in use measured under other settings only is measured again by the watch, once; the start of the
     * application does the same.
     */
    @Test
    void aChangedModelSettingIsMeasuredOnce() {
        PromptQualityMeasurements runner = measurements();
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(set, NOW(), "admin", null, QualityScheduledMeasurementPostgresTest::sound);
        QualityScheduledMeasurement scheduled = scheduled(runner, shared());

        scheduled.watch();
        assertThat(rows()).as("the settings did not change").hasSize(1);

        settings.set(OTHER_SETTINGS);
        scheduled.watch();
        scheduled.watch();
        assertThat(auto(runner, shared()).measureDecidingVersions()).as("the start finds it measuring").isEmpty();
        List<Map<String, Object>> rows = rows();
        assertThat(rows).hasSize(2);
        assertThat(rows.get(1)).containsEntry("start_reason", "SETTINGS_CHANGED")
                .containsEntry("settings_hash", QualityModelSetting.hash(OTHER_SETTINGS));
    }

    /** Two servers asking at once queue one measurement; the schedule and the watch hold locks of their own. */
    @Test
    void twoServersOnScheduleQueueOneMeasurement() throws Exception {
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(set, NOW(), "admin", null, QualityScheduledMeasurementPostgresTest::sound);
        settings.set(OTHER_SETTINGS);
        QualityScheduledMeasurement one = scheduled(measurements(), shared());
        QualityScheduledMeasurement other = scheduled(measurements(), shared());

        CompletableFuture<Void> first = CompletableFuture.runAsync(one::remeasureOnSchedule);
        CompletableFuture<Void> second = CompletableFuture.runAsync(other::remeasureOnSchedule);
        CompletableFuture.allOf(first, second).get();
        one.watch();
        other.watch();

        assertThat(rows()).hasSize(2);
        SchedulerLock schedule = QualityScheduledMeasurement.class.getMethod("remeasureOnSchedule")
                .getAnnotation(SchedulerLock.class);
        SchedulerLock watch = QualityScheduledMeasurement.class.getMethod("watch").getAnnotation(SchedulerLock.class);
        assertThat(schedule.name()).isEqualTo(QualityScheduledMeasurement.SCHEDULE_LOCK);
        assertThat(watch.name()).isEqualTo(QualityScheduledMeasurement.WATCH_LOCK).isNotEqualTo(schedule.name());
        assertThat(QualityScheduledMeasurement.class.getMethod("remeasureOnSchedule").getAnnotation(Scheduled.class)
                .cron()).isEqualTo("${contexa.pqa.oss.quality.remeasure.cron:0 0 2 * * SUN}");
    }

    /**
     * A measurement taken again is compared once with the version's measurement before: a newly missed case is a
     * change, kept with its figures; a measurement without one before is not compared; an administrator's is left.
     */
    @Test
    void aMeasurementTakenAgainIsComparedOnceWithTheOneBefore() {
        PromptQualityMeasurements runner = measurements();
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        long before = measured(set, NOW(), "admin", null, QualityScheduledMeasurementPostgresTest::sound);
        String missedKey = cases.read(set).cases().cases().stream()
                .filter(item -> item.shouldStop() && item.grade() == QualityCaseGrade.ORDINARY).findFirst()
                .orElseThrow().key();
        long later = measured(set, QualityModelSetting.hash(OTHER_SETTINGS), QualityAutoMeasurement.ACTOR,
                "SETTINGS_CHANGED", item -> item.key().equals(missedKey) ? "ALLOW" : sound(item));
        long administrators = measured(set, NOW(), "admin", null, QualityScheduledMeasurementPostgresTest::sound);
        QualityScheduledMeasurement one = scheduled(runner, shared());
        QualityScheduledMeasurement other = scheduled(runner, shared());

        assertThat(one.compareFinished()).isEqualTo(1);
        assertThat(other.compareFinished()).as("compared once").isZero();

        Map<String, Object> row = jdbc.queryForMap("select compared_measure_id, comparison, comparison_detail from"
                + " ctxa_prompt_version_measure where id = ?", later);
        assertThat(row).containsEntry("compared_measure_id", before).containsEntry("comparison", "CHANGED");
        assertThat((String) row.get("comparison_detail")).contains("\"newlyMissed\":[\"" + missedKey + "\"]")
                .contains("\"MISS\":{\"before\":[0,12],\"after\":[3,12]");
        assertThat(jdbc.queryForObject("select comparison from ctxa_prompt_version_measure where id = ?", String.class,
                administrators)).isNull();
        Optional<QualityScheduledMeasurement.Kept> latest = one.latestComparison(SCOPE, PROMPT, 2);
        assertThat(latest).hasValueSatisfying(kept -> {
            assertThat(kept.measureId()).isEqualTo(later);
            assertThat(kept.verdict()).isEqualTo(QualityRemeasureComparison.Verdict.CHANGED);
            assertThat(kept.comparedMeasureId()).isEqualTo(before);
            assertThat(kept.detail()).containsEntry("startReason", "SETTINGS_CHANGED");
        });

        // The first measurement of a version taken again has nothing before it.
        jdbc.update("delete from ctxa_prompt_version_measure where id in (?, ?, ?)", before, later, administrators);
        long alone = measured(set, NOW(), QualityAutoMeasurement.ACTOR, "SCHEDULED",
                QualityScheduledMeasurementPostgresTest::sound);
        assertThat(one.compareFinished()).isEqualTo(1);
        assertThat(jdbc.queryForObject("select comparison from ctxa_prompt_version_measure where id = ?", String.class,
                alone)).isEqualTo("NOT_COMPARED");
    }

    @Test
    void theNextScheduledMeasurementIsReadFromTheSchedule() {
        Clock wednesday = Clock.fixed(Instant.parse("2026-11-25T10:00:00Z"), ZoneOffset.UTC);
        PromptQualityMeasurements runner = measurements();
        QualityAutoMeasurement auto = auto(runner, shared());

        assertThat(new QualityScheduledMeasurement(() -> jdbc, auto, () -> runner, cases,
                QualityScheduledMeasurement.DEFAULT_CRON, 0.05, JSON, wednesday).nextScheduled())
                .isEqualTo(Instant.parse("2026-11-29T02:00:00Z"));
        assertThat(new QualityScheduledMeasurement(() -> jdbc, auto, () -> runner, cases, "-", 0.05, JSON, wednesday)
                .nextScheduled()).isNull();
    }

    // ----- fixtures -----

    private static String NOW() {
        return QualityModelSetting.hash(SETTINGS);
    }

    /** A runner of measurements that never takes its lock, so it replays nothing, under the settings of the test. */
    private PromptQualityMeasurements measurements() {
        PromptQualityRunLine line = new PromptQualityRunLine();
        lines.add(line);
        PromptQualityMeasurements runner = new PromptQualityMeasurements(() -> jdbc, versions, cases,
                (actor, given, format, version, user, organization, scope, timeZone) -> {
                    throw new IllegalStateException("Nothing is replayed in this test");
                }, line, atMostFor -> Optional.empty(), settings::get, () -> QualityClosingRules.DEFAULTS,
                new PromptQualityMeasurements.Settings(3, 1, 0, Duration.ZERO, 0, Duration.ofSeconds(60)), JSON,
                CLOCK, "server-" + opened.size());
        opened.add(runner);
        return runner;
    }

    private QualityAutoMeasurement auto(PromptQualityMeasurements runner, QualityMeasureLock lock) {
        PromptVersionResolver resolver = new PromptVersionResolver(
                new JdbcPromptGovernanceDescriptorResolver(jdbc, JSON).registrySelector(), versions, () -> null, CLOCK);
        QualityAutoMeasurement auto = new QualityAutoMeasurement(() -> jdbc, versions, cases, () -> runner,
                new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver), null, lock);
        autos.add(auto);
        return auto;
    }

    private QualityScheduledMeasurement scheduled(PromptQualityMeasurements runner, QualityMeasureLock lock) {
        return new QualityScheduledMeasurement(() -> jdbc, auto(runner, lock), () -> runner, cases,
                QualityScheduledMeasurement.DEFAULT_CRON, 0.05, JSON, CLOCK);
    }

    private static QualityMeasureLock shared() {
        return QualityMeasureLock.shedLock(new JdbcTemplateLockProvider(jdbc, "ctxa_shedlock"),
                QualityAutoMeasurement.LOCK_NAME, CLOCK);
    }

    private static String sound(QualityCase item) {
        return item.shouldStop() ? "BLOCK" : "ALLOW";
    }

    private static List<Map<String, Object>> rows() {
        return jdbc.queryForList("select id, status, start_reason, case_set_id, planned_answers, reusable_answers,"
                + " measured_anew, created_by, settings_hash from ctxa_prompt_version_measure where version_number = 2"
                + " order by id");
    }

    /** A finished measurement of v2.0 as its runner writes it: every case of the set in three runs. */
    private long measured(PromptQualityCases.PublishedSet set, String settingsHash, String createdBy,
                          String startReason, Function<QualityCase, String> action) {
        String content = versions.find(SCOPE, PROMPT, 2).orElseThrow().contentHash();
        Long id = jdbc.queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key,"
                + " version_number, version_content_hash, case_set_id, case_set_version, repeats, settings_hash,"
                + " settings, model_setting, closing_rules, status, planned_answers, reusable_answers,"
                + " expected_min_calls, expected_max_calls, call_limit, created_by, created_at, start_reason) values"
                + " (?, ?, 2, ?, ?, ?, 3, ?, '{}', ?, 'test', 'DONE', 24, 0, 24, 96, 0, ?, ?, ?) returning id",
                Long.class, SCOPE, PROMPT, content, set.id(), set.version(), settingsHash,
                "settings=" + settingsHash + ";models=model-a", createdBy,
                Timestamp.from(CLOCK.instant().plusMillis(jdbc.queryForObject("select count(*) from"
                        + " ctxa_prompt_version_measure", Long.class))), startReason);
        for (QualityCase item : cases.read(set).cases().cases()) {
            for (int run = 1; run <= 3; run++) {
                String answer = action.apply(item);
                jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                        + " case_content_hash, version_number, version_content_hash, settings_hash, run_number,"
                        + " first_action, final_action, cited_facts, accurate_cited_facts, answered_model, created_at)"
                        + " values (?, ?, ?, ?, 2, ?, ?, ?, ?, ?, 3, 3, 'model-a', ?)", id, SCOPE, item.key(),
                        item.contentHash(), content, settingsHash, run, answer, answer,
                        Timestamp.from(CLOCK.instant()));
            }
        }
        return id;
    }
}
