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
package io.contexa.contexaiam.admin.promptquality.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseSealedForm;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityRunLine;
import io.contexa.contexaiam.admin.promptquality.measure.QualityAutoMeasurement;
import io.contexa.contexaiam.admin.promptquality.measure.QualityMeasureLock;
import io.contexa.contexaiam.admin.promptquality.measure.QualityModelSetting;
import io.contexa.contexaiam.admin.promptquality.measure.QualityScheduledMeasurement;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.VersionChange;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.VersionRate;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustDecisionRecords;
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
import java.sql.Date;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Quality plan 3.6 on a database with the schema of a new installation: the state of quality gives the latest
 * measurement of the version in use with numerator and denominator, its operation metrics beside those of the
 * version it replaced from the hourly table, the second-analysis cases counted apart, and what there is to check.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityStatusPostgresTest {

    private static final String SCOPE = PromptVersionService.PLATFORM_SCOPE;
    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-11-22T12:30:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Map<String, String> SETTINGS = Map.of("layer1.model", "model-a", "timeZone", "UTC");
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
                + " ctxa_prompt_version, ctxa_prompt_governance_registry, ctxa_shedlock, ctxa_zt_stats_hourly,"
                + " ctxa_zt_review_queue, ctxa_sealed_evidence_package CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), TARGETS,
                PromptVersionAudit.none(), CLOCK);
        versions.registerProducts(null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Payroll\nsystem:\n"
                + "  - key: how-to-judge\n    text: |\n      1. Weigh the payroll roster first.\n",
                PromptVersionRecord.SCREEN, null, "admin", null);
        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'ACTIVE', updated_at = ? where"
                + " prompt_version = 'v2.0'", Timestamp.from(NOW));
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
     * The latest measurement of the version in use, its rates with numerator and denominator on both bases, and the
     * six operation metrics of the week after the version took over beside the week before, each version's own.
     */
    @Test
    void theMeasurementAndTheOperationMetricsAroundTheChangeAreGivenWithTheirCounts() {
        PromptQualityMeasurements runner = measurements();
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        String missedKey = cases.read(set).cases().cases().stream().filter(QualityCase::shouldStop).findFirst()
                .orElseThrow().key();
        long id = measured(set, SETTINGS, null, item -> item.key().equals(missedKey) ? "ALLOW" : sound(item));
        operationHours();
        jdbc.update("INSERT INTO ctxa_zt_review_queue (observation_id, sample_day, review_reason) VALUES ('d-1', ?,"
                + " 'SAMPLE')", Date.valueOf("2026-11-21"));

        PromptQualityStatus.Status status = status(runner).status(null, "week", null);

        assertThat(status.version()).isEqualTo("v2.0");
        assertThat(status.state()).isEqualTo(QualityMeasurementState.MEASURED);
        assertThat(status.measurement().id()).isEqualTo(id);
        assertThat(status.measurement().fresh()).isTrue();
        assertThat(status.measurement().changedSettings()).isEmpty();
        PromptQualityStatus.Rate miss = status.measurement().firstAnswer().rates().get("MISS");
        assertThat(miss.events()).isEqualTo(3);
        assertThat(miss.trials()).isEqualTo(12);
        assertThat(miss.value()).isEqualTo(0.25);
        assertThat(miss.lower()).isNotNull().isLessThan(0.25);
        assertThat(miss.upper()).isNotNull().isGreaterThan(0.25);
        assertThat(status.measurement().finalAction().rates().get("FALSE_STOP").trials()).isEqualTo(12);
        assertThat(status.measurement().firstAnswer().decisionMillis().count()).isEqualTo(24);

        VersionChange change = status.operation();
        assertThat(change.previousVersion()).isEqualTo("v1.0");
        assertThat(change.firstSeen()).isEqualTo("2026-11-15T03:00:00Z");
        assertThat(change.changedAt()).isEqualTo("2026-11-15T06:00:00Z");
        assertThat(change.beforeFrom()).isEqualTo("2026-11-08T06:00:00Z");
        assertThat(change.afterTo()).isEqualTo("2026-11-22T06:00:00Z");
        assertThat(change.rates()).extracting(VersionRate::key, VersionRate::beforeEvents, VersionRate::beforeTrials,
                VersionRate::afterEvents, VersionRate::afterTrials).containsExactly(
                tuple("STOPPED", 20L, 112L, 30L, 120L),
                tuple("CHALLENGE_PASS", 12L, 15L, 18L, 20L),
                tuple("BLOCK_RELEASE", 1L, 5L, 2L, 10L),
                tuple("REVIEW_VALID", 3L, 4L, 5L, 5L),
                tuple("RETRY", 4L, 112L, 2L, 120L),
                tuple("MODEL_LESS", 2L, 112L, 0L, 120L));
        assertThat(status.toCheck()).extracting(PromptQualityStatus.ToCheck::kind).containsExactly("REVIEW_PENDING");
        assertThat(status.pendingReviews()).isEqualTo(1);
        assertThat(status.nextScheduled()).isEqualTo(Instant.parse("2026-11-29T02:00:00Z"));
    }

    /**
     * A version measured under other settings only is stale, with the settings that differ; one measured again that
     * came out worse comes first among the things to check; waiting cases are named.
     */
    @Test
    void aStaleMeasurementAndAWorseMeasurementTakenAgainAreToCheckWorstFirst() {
        PromptQualityMeasurements runner = measurements();
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        long id = measured(set, SETTINGS, "SCHEDULED", PromptQualityStatusPostgresTest::sound);
        jdbc.update("update ctxa_prompt_version_measure set comparison = 'WORSE', compared_at = ?,"
                + " comparison_detail = '{\"verdict\":\"WORSE\",\"newlyFailedGraded\":[\"A1\"]}' where id = ?",
                Timestamp.from(NOW), id);
        PromptQualityCases waiting = new PromptQualityCases(() -> jdbc, JSON, true, PromptVersionAudit.none(), CLOCK,
                null, () -> cases.defaultSet());
        QualityCase source = cases.defaultSet().cases().get(0);
        waiting.copy(SCOPE, PROMPT, source.key(), null, source.expectation(), source.grade(), "admin");
        settings.set(Map.of("layer1.model", "model-b", "timeZone", "UTC"));

        PromptQualityStatus.Status status = status(runner).status(SCOPE, "week", null);

        assertThat(status.state()).isEqualTo(QualityMeasurementState.STALE);
        assertThat(status.measurement().fresh()).isFalse();
        assertThat(status.measurement().changedSettings()).containsExactly(
                Map.entry("layer1.model", Arrays.asList("model-a", "model-b")));
        assertThat(status.toCheck()).extracting(PromptQualityStatus.ToCheck::kind, PromptQualityStatus.ToCheck::severity)
                .containsExactly(tuple("REMEASURE_WORSE", "BAD"), tuple("MEASUREMENT_STALE", "WARN"),
                        tuple("CASES_PENDING", "WARN"));
        assertThat(status.toCheck().get(0).figures()).containsEntry("measureId", id)
                .containsEntry("newlyFailedGraded", List.of("A1"));
        assertThat(status.cases().pending()).isEqualTo(1);
        assertThat(status.operation().previousVersion()).as("no decision in the hourly table").isNull();
        assertThat(status.operation().rates()).allSatisfy(rate -> assertThat(rate.afterTrials()).isZero());
    }

    /** Without a measurement: one waiting is the baseline pending, none is missing, no runner cannot measure. */
    @Test
    void withoutAMeasurementItIsWaitedForMissingOrCannotBeMeasured() {
        PromptQualityMeasurements runner = measurements();
        cases.publishDefault(SCOPE, PROMPT, "admin");

        assertThat(status(runner).status(SCOPE, null, null).state()).isEqualTo(QualityMeasurementState.MISSING);
        runner.start(SCOPE, PROMPT, 2, null, null, "admin");
        PromptQualityStatus.Status waiting = status(runner).status(SCOPE, null, null);
        assertThat(waiting.state()).isEqualTo(QualityMeasurementState.BASELINE_PENDING);
        assertThat(waiting.measuring()).isTrue();
        assertThat(waiting.toCheck()).extracting(PromptQualityStatus.ToCheck::kind).containsExactly("BASELINE_PENDING");
        PromptQualityStatus.Status unmeasurable = new PromptQualityStatus(versions, catalog(), cases, () -> null,
                () -> null, () -> null, () -> null).status(SCOPE, null, null);
        assertThat(unmeasurable.state()).isEqualTo(QualityMeasurementState.UNMEASURABLE);
        assertThat(unmeasurable.operation()).isNull();
        assertThat(unmeasurable.nextScheduled()).isNull();
    }

    /**
     * Quality plan 3.6 (supplement P-4): the decisions this server left unsealed, by the full queue and over the daily
     * limit, are to check with both counts; with none missed, or nothing here that seals, there is nothing of them.
     */
    @Test
    void theDecisionsThisServerLeftUnsealedAreToCheck() {
        PromptQualityStatus.Status missed = new PromptQualityStatus(versions, catalog(), cases, () -> null,
                () -> null, () -> null, () -> null, () -> new PromptQualityStatus.SealMisses(2, 3))
                .status(SCOPE, null, null);
        assertThat(missed.toCheck()).extracting(PromptQualityStatus.ToCheck::kind, PromptQualityStatus.ToCheck::severity,
                PromptQualityStatus.ToCheck::count).containsExactly(tuple("SEAL_MISSED", "WARN", 5L),
                tuple("UNMEASURABLE", "INFO", 1L));
        assertThat(missed.toCheck().get(0).figures()).containsEntry("queueFull", 2L)
                .containsEntry("overDailyLimit", 3L);
        for (PromptQualityStatus none : List.of(new PromptQualityStatus(versions, catalog(), cases, () -> null,
                () -> null, () -> null, () -> null, () -> PromptQualityStatus.SealMisses.NONE),
                new PromptQualityStatus(versions, catalog(), cases, () -> null, () -> null, () -> null, () -> null,
                        () -> null))) {
            assertThat(none.status(SCOPE, null, null).toCheck()).extracting(PromptQualityStatus.ToCheck::kind)
                    .containsExactly("UNMEASURABLE");
        }
    }

    /** The cases promoted from a decision the second analysis decided are counted apart, with their own rates. */
    @Test
    void theCasesOfTheSecondAnalysisAreCountedApartInTheMeasurement() {
        PromptQualityMeasurements runner = measurements();
        QualityCase threat = cases.defaultSet().cases().stream().filter(QualityCase::shouldStop).findFirst()
                .orElseThrow();
        SealedEvidencePackage sealed = QualityCaseSealedForm.sealed(threat);
        sealed.setPackageId("package-second");
        sealed.setDecisionJson("{\"aiAnalysisLevel\":2}");
        PromptQualityCases.Kept kept = cases.promote(SCOPE, PROMPT, sealed, null, null, threat.expectation(),
                threat.grade(), "admin");
        PromptQualityCases.PublishedSet set = cases.publish(SCOPE, PROMPT, "admin");
        measured(set, SETTINGS, null, item -> item.key().equals(kept.key()) ? "ALLOW" : sound(item));

        PromptQualityStatus.Measurement measurement = status(runner).status(SCOPE, null, null).measurement();

        assertThat(kept.secondAnalysis()).isTrue();
        assertThat(measurement.secondAnalysisCases()).containsExactly(kept.key());
        assertThat(measurement.secondAnalysisFirstAnswer().rates().get("MISS"))
                .satisfies(rate -> assertThat(List.of(rate.events(), rate.trials())).containsExactly(3L, 3L));
        assertThat(measurement.firstAnswer().rates().get("MISS").trials()).isEqualTo(15);
        assertThat(status(runner).status(SCOPE, null, null).cases().secondAnalysis()).isEqualTo(1);
    }

    // ----- fixtures -----

    /**
     * v0.9 decided long before, v1.0 until 05:00 on 11-15, v2.0 from a canary at 03:00 that day: the change is at
     * 06:00. A request with no decision and an hour after the week are not counted.
     */
    private static void operationHours() {
        hour("v0.9", "2026-10-01T10:00:00Z", "ALLOW", "MODEL", 50, 0, 0, 0, 0, 0);
        hour("v1.0", "2026-11-14T10:00:00Z", "ALLOW", "MODEL", 80, 0, 0, 0, 0, 4);
        hour("v1.0", "2026-11-14T10:00:00Z", "CHALLENGE", "MODEL", 15, 12, 0, 0, 0, 0);
        hour("v1.0", "2026-11-14T10:00:00Z", "BLOCK", "MODEL", 5, 0, 1, 3, 1, 0);
        hour("v1.0", "2026-11-14T10:00:00Z", "ALLOW", "MODEL_LESS", 2, 0, 0, 0, 0, 0);
        hour("v1.0", "2026-11-15T05:00:00Z", "ALLOW", "MODEL", 10, 0, 0, 0, 0, 0);
        hour("v2.0", "2026-11-15T03:00:00Z", "ALLOW", "MODEL", 5, 0, 0, 0, 0, 0);
        hour("v2.0", "2026-11-18T09:00:00Z", "ALLOW", "MODEL", 90, 0, 0, 0, 0, 2);
        hour("v2.0", "2026-11-18T09:00:00Z", "CHALLENGE", "MODEL", 20, 18, 0, 0, 0, 0);
        hour("v2.0", "2026-11-18T09:00:00Z", "BLOCK", "MODEL", 10, 0, 2, 5, 0, 0);
        hour("v2.0", "2026-11-18T09:00:00Z", "NO_DECISION", "", 9, 0, 0, 0, 0, 0);
        hour("v2.0", "2026-11-22T08:00:00Z", "ALLOW", "MODEL", 7, 0, 0, 0, 0, 0);
    }

    private static void hour(String version, String at, String action, String source, long decisions, long passed,
                             long released, long valid, long invalid, long retried) {
        jdbc.update("INSERT INTO ctxa_zt_stats_hourly (bucket_start, final_action, decision_source,"
                + " prompt_bundle_version, decision_count, challenge_passed_count, admin_released_count,"
                + " evaluated_valid_count, evaluated_invalid_count, retried_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                Timestamp.from(Instant.parse(at)), action, source, version, decisions, passed, released, valid, invalid,
                retried);
    }

    private PromptQualityStatus status(PromptQualityMeasurements runner) {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        ZeroTrustConsoleService console = new ZeroTrustConsoleService(() -> jdbc, properties, null, JSON, () -> null,
                true, CLOCK);
        ZeroTrustDecisionRecords records = new ZeroTrustDecisionRecords(() -> jdbc,
                new ZeroTrustDecisionOutcomes(() -> jdbc, CLOCK), null, JSON, CLOCK);
        QualityAutoMeasurement auto = new QualityAutoMeasurement(() -> jdbc, versions, cases, () -> runner, catalog(),
                null, QualityMeasureLock.local());
        autos.add(auto);
        QualityScheduledMeasurement scheduled = new QualityScheduledMeasurement(() -> jdbc, auto, () -> runner, cases,
                QualityScheduledMeasurement.DEFAULT_CRON, 0.05, JSON, CLOCK);
        return new PromptQualityStatus(versions, catalog(), cases, () -> runner, () -> scheduled, () -> console,
                () -> records);
    }

    private JdbcPromptVersionCatalog catalog() {
        PromptVersionResolver resolver = new PromptVersionResolver(
                new JdbcPromptGovernanceDescriptorResolver(jdbc, JSON).registrySelector(), versions, () -> null, CLOCK);
        return new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver);
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

    private static String sound(QualityCase item) {
        return item.shouldStop() ? "BLOCK" : "ALLOW";
    }

    /** A finished measurement of v2.0 under the settings: every case of the set in three runs. */
    private long measured(PromptQualityCases.PublishedSet set, Map<String, String> under, String startReason,
                          Function<QualityCase, String> action) {
        String content = versions.find(SCOPE, PROMPT, 2).orElseThrow().contentHash();
        String hash = QualityModelSetting.hash(under);
        String written;
        try {
            written = JSON.writeValueAsString(under);
        }
        catch (Exception unwritable) {
            throw new IllegalStateException(unwritable);
        }
        Long id = jdbc.queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key,"
                + " version_number, version_content_hash, case_set_id, case_set_version, repeats, settings_hash,"
                + " settings, model_setting, closing_rules, status, planned_answers, reusable_answers,"
                + " expected_min_calls, expected_max_calls, call_limit, created_by, created_at, finished_at,"
                + " start_reason) values (?, ?, 2, ?, ?, ?, 3, ?, ?, ?, 'test', 'DONE', 24, 0, 24, 96, 0, 'admin', ?,"
                + " ?, ?) returning id", Long.class, SCOPE, PROMPT, content, set.id(), set.version(), hash, written,
                "settings=" + hash + ";models=model-a", Timestamp.from(NOW), Timestamp.from(NOW), startReason);
        for (QualityCase item : cases.read(set).cases().cases()) {
            for (int run = 1; run <= 3; run++) {
                String answer = action.apply(item);
                jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                        + " case_content_hash, version_number, version_content_hash, settings_hash, run_number,"
                        + " first_action, final_action, cited_facts, accurate_cited_facts, decision_ms, answered_model,"
                        + " created_at) values (?, ?, ?, ?, 2, ?, ?, ?, ?, ?, 3, 3, 7000, 'model-a', ?)", id, SCOPE,
                        item.key(), item.contentHash(), content, hash, run, answer, answer, Timestamp.from(NOW));
            }
        }
        return id;
    }
}
