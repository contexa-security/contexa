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
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateMode;
import io.contexa.contexacore.std.components.prompt.quality.QualityGatePolicy;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateReading;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSide;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateStatus;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityShippedMeasurements;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.QualityCaseName;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.QualityDetails;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.QualityProgress;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.4 on a database with the schema of a new installation: what the quality gate reads from the store of the
 * measurements (the five states, the pair compared, the noise of two measurements whose answers are their own, the
 * measurements shipped with the product, what a version that decides outside the gate shows), and the measurements
 * Contexa starts by itself (the case set published for them, once per version and setting, under one lock for the
 * servers, for the versions outside the gate and the version in use right after an upgrade). The measurements are
 * written as their runner writes them, and the runner never takes its lock, so nothing is replayed.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class QualityGateSourcePostgresTest {

    private static final String SCOPE = PromptVersionService.PLATFORM_SCOPE;
    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Clock CLOCK = Clock.systemUTC();
    private static final Map<String, String> SETTINGS = Map.of("layer1.model", "model-a");
    private static final String NOW = QualityModelSetting.hash(SETTINGS);
    private static final String BEFORE = QualityModelSetting.hash(Map.of("layer1.model", "model-before"));
    private static final QualityGateSettings FEW_ROOTS = new QualityGateSettings(0.05, 0.05, 1, 1);
    private static QualityCaseSet all;
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private final List<PromptQualityMeasurements> opened = new CopyOnWriteArrayList<>();
    private final List<PromptQualityRunLine> lines = new CopyOnWriteArrayList<>();
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

    /** v1.0 is the product version, v2.0 and v3.0 an organization's versions on it. */
    @BeforeEach
    void threeVersions() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_case_cause, ctxa_prompt_version_measure_prompt,"
                + " ctxa_prompt_version_measure_answer, ctxa_prompt_version_measure, ctxa_prompt_version_case_set_member,"
                + " ctxa_prompt_version_case_set, ctxa_prompt_version_case_change, ctxa_prompt_version_case,"
                + " ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_governance_registry, ctxa_shedlock CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), TARGETS,
                PromptVersionAudit.none(), CLOCK);
        versions.registerProducts(null);
        for (String title : List.of("Finance closing", "Payroll")) {
            versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: " + title + "\nsystem:\n"
                    + "  - key: how-to-judge\n    text: |\n      1. Weigh the " + title + " roster first.\n",
                    PromptVersionRecord.SCREEN, null, "admin", null);
        }
    }

    @AfterEach
    void closeAll() {
        opened.forEach(PromptQualityMeasurements::close);
        lines.forEach(PromptQualityRunLine::close);
    }

    // ----- what the gate reads -----

    @Test
    void withoutARunnerNothingCanBeMeasuredAndWithoutAPublishedSetNothingIsMeasured() {
        PromptQualityCases cases = cases(8);

        QualityGateReading noRunner = new MeasuredQualityGateSource(() -> jdbc, versions, cases, () -> null, null)
                .read(SCOPE, PROMPT, "v2.0", "v1.0");
        QualityGateReading nothing = source(cases, measurements(cases, 0)).read(SCOPE, PROMPT, "v2.0", "v1.0");

        assertThat(noRunner.state()).isEqualTo(QualityMeasurementState.UNMEASURABLE);
        assertThat(noRunner.detail()).isEqualTo(MeasuredQualityGateSource.NO_MEASUREMENT_RUNNER);
        assertThat(nothing.state()).isEqualTo(QualityMeasurementState.MISSING);
        assertThat(nothing.sides()).containsExactlyInAnyOrder(QualityGateSide.CANDIDATE, QualityGateSide.CURRENT);
        assertThat(nothing.detail()).isEqualTo(MeasuredQualityGateSource.NO_CASE_SET);
        assertThat(nothing.input()).isNull();
    }

    @Test
    void twoFreshMeasurementsTakenTheSameWayAreComparedWithTheCasesAndWhenTheCandidateWasMade() {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(set, 1, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);
        long inUse = measured(set, 1, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);
        // A newer measurement of the version in use whose answer came from another model is not the one compared.
        measured(set, 1, NOW, "model-fallback", "admin", QualityGateSourcePostgresTest::sound);
        long candidate = measured(set, 2, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);

        QualityGateReading reading = source(cases, runner).read(SCOPE, PROMPT, "v2.0", "v1.0");

        assertThat(reading.state()).isEqualTo(QualityMeasurementState.MEASURED);
        assertThat(reading.detail()).isNull();
        assertThat(reading.input().cases()).hasSize(8);
        assertThat(reading.input().candidate().promptVersion()).isEqualTo("v2.0");
        assertThat(reading.input().candidate().answers()).hasSize(8 * 3);
        assertThat(reading.input().current().promptVersion()).isEqualTo("v1.0");
        assertThat(reading.input().current().modelSetting()).isEqualTo("settings=" + NOW + ";models=model-a");
        assertThat(reading.input().current().comparableWith(reading.input().candidate())).isTrue();
        assertThat(reading.input().candidateCreatedAt()).isEqualTo(versions.find(SCOPE, PROMPT, 2).orElseThrow()
                .createdAt());
        assertThat(inUse).isNotEqualTo(candidate);
        // The gate computes its verdict from it with its own thresholds.
        assertThat(new QualityGatePolicy(source(cases, runner), QualityGateMode.BLOCK, FEW_ROOTS)
                .assess(SCOPE, PROMPT, "v2.0", "v1.0").applied()).isEqualTo(QualityGateStatus.PASSED);
    }

    @Test
    void theNoiseIsTakenFromTwoMeasurementsOfOneVersionWhoseAnswersAreTheirOwn() {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        long first = measured(set, 1, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);
        measured(set, 2, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);

        // A second measurement that used every answer of the first again shows no noise.
        reusing(first, set);
        assertThat(source(cases, runner).read(SCOPE, PROMPT, "v2.0", "v1.0").input().noise().widths()).isEmpty();

        // A second measurement with answers of its own, one threat let through in one run.
        String threat = cases.read(set).cases().cases().stream().filter(QualityCase::shouldStop).findFirst()
                .orElseThrow().key();
        measured(set, 1, NOW, "model-a", "admin", item -> item.key().equals(threat) ? "ALLOW" : sound(item), 1);

        QualityGateReading reading = source(cases, runner).read(SCOPE, PROMPT, "v2.0", "v1.0");

        assertThat(reading.input().noise().width(QualityMetric.MISS)).isPresent();
        assertThat(reading.input().noise().width(QualityMetric.MISS).getAsDouble()).isGreaterThan(0.0);
    }

    @Test
    void theFirstMeasurementOfTheVersionInUseWaitingIsBaselinePendingAndNoneWaitingIsMissing() {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(set, 2, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);

        QualityGateReading missing = source(cases, runner).read(SCOPE, PROMPT, "v2.0", "v1.0");
        measure(set, 1, NOW, null, PromptQualityMeasurements.QUEUED, QualityAutoMeasurement.ACTOR);
        QualityGateReading pending = source(cases, runner).read(SCOPE, PROMPT, "v2.0", "v1.0");

        assertThat(missing.state()).isEqualTo(QualityMeasurementState.MISSING);
        assertThat(missing.sides()).containsExactly(QualityGateSide.CURRENT);
        assertThat(pending.state()).isEqualTo(QualityMeasurementState.BASELINE_PENDING);
        assertThat(pending.sides()).containsExactly(QualityGateSide.CURRENT);
        assertThat(pending.detail()).isEqualTo(MeasuredQualityGateSource.MEASURING);
        assertThat(pending.input().current()).isNull();
        assertThat(pending.input().candidate().promptVersion()).isEqualTo("v2.0");
    }

    @Test
    void aMeasurementTakenUnderOtherServerSettingsIsStaleAndOneMeasuringAgainIsNamed() {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(set, 1, BEFORE, "model-before", "admin", QualityGateSourcePostgresTest::sound);
        measured(set, 2, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);

        QualityGateReading stale = source(cases, runner).read(SCOPE, PROMPT, "v2.0", "v1.0");
        measure(set, 1, NOW, null, PromptQualityMeasurements.RUNNING, "admin");
        QualityGateReading measuring = source(cases, runner).read(SCOPE, PROMPT, "v2.0", "v1.0");

        assertThat(stale.state()).isEqualTo(QualityMeasurementState.STALE);
        assertThat(stale.sides()).containsExactly(QualityGateSide.CURRENT);
        assertThat(stale.detail()).isNull();
        assertThat(stale.input().current().modelSetting()).contains(BEFORE);
        assertThat(measuring.state()).isEqualTo(QualityMeasurementState.STALE);
        assertThat(measuring.detail()).isEqualTo(MeasuredQualityGateSource.MEASURING);
        // The two are not taken the same way: the gate blocks on its first condition, warned of as stale.
        assertThat(new QualityGatePolicy(source(cases, runner), QualityGateMode.BLOCK, FEW_ROOTS)
                .assess(SCOPE, PROMPT, "v2.0", "v1.0").applied()).isEqualTo(QualityGateStatus.BLOCKED);
    }

    /**
     * Plan 3.4 and the approved confirmation: beside the verdict it names the version of the case set the
     * measurements are taken on, the models of the measurements compared and of the server now, the measurement of
     * the version in use that waits with its answers so far, and the cases by what their request asked.
     */
    @Test
    void theDetailsNameTheCaseSetTheModelsTheWaitingBaselineWithItsProgressAndTheCases() {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(set, 2, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);
        long waiting = measure(set, 1, NOW, null, PromptQualityMeasurements.QUEUED, QualityAutoMeasurement.ACTOR);
        QualityCase first = cases.read(set).cases().cases().get(0);
        String content = versions.find(SCOPE, PROMPT, 1).orElseThrow().contentHash();
        for (int run = 1; run <= 2; run++) {
            jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                    + " case_content_hash, version_number, version_content_hash, settings_hash, run_number,"
                    + " first_action, final_action, cited_facts, accurate_cited_facts, answered_model, created_at)"
                    + " values (?, ?, ?, ?, 1, ?, ?, ?, 'BLOCK', 'BLOCK', 3, 3, 'model-a', ?)", waiting, SCOPE,
                    first.key(), first.contentHash(), content, NOW, run, Timestamp.from(CLOCK.instant()));
        }

        QualityDetails details = source(cases, runner).details(SCOPE, PROMPT, "v2.0", "v1.0",
                List.of(first.key(), "no-such-case"));

        assertThat(details.caseSetVersion()).isEqualTo(set.version());
        assertThat(details.models()).isEqualTo("model-a");
        assertThat(details.modelsBefore()).isNull();
        assertThat(details.modelsNow()).isEqualTo("model-a");
        assertThat(details.measuring()).isEqualTo(new QualityProgress("v1.0", 2, 24));
        assertThat(details.caseNames()).extracting(QualityCaseName::key).containsExactly(first.key(), "no-such-case");
        assertThat(details.caseNames().get(0).name()).matches("[A-Z]+ /\\S+ \\(" + first.key() + "\\)");
        assertThat(details.caseNames().get(1).name()).isEqualTo("no-such-case");
        // The verdict is the gate's: the reading of the same versions is the baseline waiting, as before.
        assertThat(source(cases, runner).read(SCOPE, PROMPT, "v2.0", "v1.0").state())
                .isEqualTo(QualityMeasurementState.BASELINE_PENDING);
    }

    /** A measurement stale under the settings of now names the models it was answered by and the models of now. */
    @Test
    void theDetailsOfAStaleMeasurementNameTheModelsBeforeAndNow() {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(set, 1, BEFORE, "model-before", "admin", QualityGateSourcePostgresTest::sound);
        measured(set, 2, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);

        QualityDetails details = source(cases, runner).details(SCOPE, PROMPT, "v2.0", "v1.0", List.of());

        assertThat(details.modelsBefore()).isEqualTo("model-before");
        assertThat(details.modelsNow()).isEqualTo("model-a");
        assertThat(details.measuring()).isNull();
        assertThat(details.caseNames()).isEmpty();
        assertThat(MeasuredQualityGateSource.models("settings=abc;models=m1,m2")).isEqualTo("m1, m2");
        assertThat(MeasuredQualityGateSource.models("settings=abc;models=unknown")).isNull();
        // Without a runner of measurements there is nothing to name.
        assertThat(new MeasuredQualityGateSource(() -> jdbc, versions, cases, () -> null, null)
                .details(SCOPE, PROMPT, "v2.0", "v1.0", List.of())).isNull();
    }

    @Test
    void aShippedMeasurementOfTheSameContentCaseSetAndSettingsIsReadAndOtherwiseNot() throws Exception {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(set, 2, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);
        String product = versions.find(SCOPE, PROMPT, 1).orElseThrow().contentHash();

        QualityGateReading shipped = new MeasuredQualityGateSource(() -> jdbc, versions, cases, () -> runner,
                shippedOf(product, set.version(), NOW, cases.read(set).cases().cases())).read(SCOPE, PROMPT, "v2.0",
                "v1.0");
        QualityGateReading otherSettings = new MeasuredQualityGateSource(() -> jdbc, versions, cases, () -> runner,
                shippedOf(product, set.version(), BEFORE, cases.read(set).cases().cases())).read(SCOPE, PROMPT,
                "v2.0", "v1.0");

        assertThat(shipped.state()).isEqualTo(QualityMeasurementState.MEASURED);
        assertThat(shipped.detail()).isEqualTo(MeasuredQualityGateSource.SHIPPED);
        assertThat(shipped.input().current().promptVersion()).isEqualTo("v1.0");
        assertThat(shipped.input().current().answers()).hasSize(8 * 3);
        assertThat(otherSettings.state()).isEqualTo(QualityMeasurementState.MISSING);
        assertThat(otherSettings.sides()).containsExactly(QualityGateSide.CURRENT);
    }

    @Test
    void aVersionReadAloneIsMeasuredMissingOrMeasuring() {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measure(set, 3, NOW, null, PromptQualityMeasurements.QUEUED, QualityAutoMeasurement.ACTOR);
        measured(set, 1, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);

        QualityGateReading measuring = source(cases, runner).read(SCOPE, PROMPT, "v3.0", null);
        QualityGateReading measuredAlone = source(cases, runner).read(SCOPE, PROMPT, "v1.0", null);

        assertThat(measuring.state()).isEqualTo(QualityMeasurementState.MISSING);
        assertThat(measuring.sides()).containsExactly(QualityGateSide.CANDIDATE);
        assertThat(measuring.detail()).isEqualTo(MeasuredQualityGateSource.MEASURING);
        assertThat(measuredAlone.state()).isEqualTo(QualityMeasurementState.MEASURED);
        assertThat(measuredAlone.input().current()).isNull();
    }

    /** Plan 3.4: what one read of the gate costs, on the default set of the product, measured twice per version. */
    @Test
    void theCostOfOneReadOnTheDefaultSet() {
        PromptQualityCases cases = new PromptQualityCases(() -> jdbc, JSON, false, PromptVersionAudit.none(), CLOCK,
                null, () -> all);
        PromptQualityMeasurements runner = measurements(cases, 0);
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        measured(set, 1, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);
        measured(set, 1, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);
        measured(set, 2, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);
        MeasuredQualityGateSource source = source(cases, runner);
        source.read(SCOPE, PROMPT, "v2.0", "v1.0");

        List<Long> millis = new ArrayList<>();
        for (int read = 0; read < 5; read++) {
            long started = System.nanoTime();
            QualityGateReading reading = source.read(SCOPE, PROMPT, "v2.0", "v1.0");
            millis.add(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
            assertThat(reading.input().cases()).hasSize(all.cases().size());
        }
        millis.sort(Long::compare);
        System.out.println("[QualityGateSourceCost] cases=" + all.cases().size() + " answers per measurement="
                + all.cases().size() * 3 + " reads(ms)=" + millis + " median=" + millis.get(2));
        assertThat(millis.get(2)).isLessThan(3_000L);
    }

    // ----- the measurements Contexa starts by itself -----

    @Test
    void aVersionIsMeasuredOnceForItsContentCaseSetAndSettingsOnTheDefaultSetPublishedForIt() throws Exception {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        QualityAutoMeasurement auto = auto(cases, () -> runner, shared(), QualityShippedMeasurements.none());

        QualityAutoMeasurement.Result queued = auto.request(SCOPE, PROMPT, "v2.0",
                QualityAutoMeasurement.Reason.OUTSIDE_GATE);
        QualityAutoMeasurement.Result again = auto.request(SCOPE, PROMPT, "v2.0",
                QualityAutoMeasurement.Reason.OUTSIDE_GATE);

        assertThat(queued.outcome()).isEqualTo(QualityAutoMeasurement.Outcome.QUEUED);
        assertThat(again.outcome()).isEqualTo(QualityAutoMeasurement.Outcome.QUEUED_ALREADY);
        assertThat(again.measureId()).isEqualTo(queued.measureId());
        PromptQualityCases.PublishedSet set = cases.latestPublished(SCOPE, PROMPT).orElseThrow();
        assertThat(set.publishedBy()).isEqualTo(QualityAutoMeasurement.ACTOR);
        assertThat(set.version()).isEqualTo(cases.defaultSet().version());
        assertThat(jdbc.queryForMap("select created_by, status, case_set_id, settings_hash from"
                + " ctxa_prompt_version_measure where id = ?", queued.measureId()))
                .containsEntry("created_by", QualityAutoMeasurement.ACTOR)
                .containsEntry("status", PromptQualityMeasurements.QUEUED)
                .containsEntry("case_set_id", set.id()).containsEntry("settings_hash", NOW);

        jdbc.update("update ctxa_prompt_version_measure set status = ? where id = ?", PromptQualityMeasurements.FAILED,
                queued.measureId());
        assertThat(auto.request(SCOPE, PROMPT, "v2.0", QualityAutoMeasurement.Reason.OUTSIDE_GATE).outcome())
                .as("tried once").isEqualTo(QualityAutoMeasurement.Outcome.TRIED_ONCE);
        measured(set, 3, NOW, "model-a", "admin", QualityGateSourcePostgresTest::sound);
        assertThat(auto.request(SCOPE, PROMPT, "v3.0", QualityAutoMeasurement.Reason.BASELINE).outcome())
                .isEqualTo(QualityAutoMeasurement.Outcome.MEASURED_ALREADY);
        String product = versions.find(SCOPE, PROMPT, 1).orElseThrow().contentHash();
        assertThat(auto(cases, () -> runner, shared(), shippedOf(product, set.version(), NOW,
                cases.read(set).cases().cases())).request(SCOPE, PROMPT, "v1.0",
                QualityAutoMeasurement.Reason.OUTSIDE_GATE).outcome()).isEqualTo(QualityAutoMeasurement.Outcome.SHIPPED);
        assertThat(auto(cases, () -> null, shared(), null).request(SCOPE, PROMPT, "v1.0",
                QualityAutoMeasurement.Reason.OUTSIDE_GATE).outcome())
                .isEqualTo(QualityAutoMeasurement.Outcome.NO_RUNNER);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_measure", Integer.class))
                .isEqualTo(2);
    }

    @Test
    void aMeasurementTheLimitRefusesIsNotQueuedAndAHeldLockIsBusy() {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements limited = measurements(cases, 1);

        QualityAutoMeasurement.Result refused = auto(cases, () -> limited, shared(), null).request(SCOPE, PROMPT,
                "v2.0", QualityAutoMeasurement.Reason.OUTSIDE_GATE);
        QualityAutoMeasurement.Result busy = auto(cases, () -> limited, atMostFor -> Optional.empty(), null)
                .request(SCOPE, PROMPT, "v2.0", QualityAutoMeasurement.Reason.OUTSIDE_GATE);

        assertThat(refused.outcome()).isEqualTo(QualityAutoMeasurement.Outcome.REFUSED);
        assertThat(refused.detail()).isEqualTo(PromptQualityMeasurements.Refusal.CALL_LIMIT.name());
        assertThat(busy.outcome()).isEqualTo(QualityAutoMeasurement.Outcome.BUSY);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_measure", Integer.class)).isZero();
    }

    @Test
    void twoServersAskingAtOnceQueueOneMeasurement() throws Exception {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements serverA = measurements(cases, 0);
        PromptQualityMeasurements serverB = measurements(cases, 0);
        QualityAutoMeasurement autoA = auto(cases, () -> serverA, shared(), null);
        QualityAutoMeasurement autoB = auto(cases, () -> serverB, shared(), null);
        cases.publishDefault(SCOPE, PROMPT, "admin");

        for (int round = 0; round < 5; round++) {
            CompletableFuture<QualityAutoMeasurement.Result> a = CompletableFuture.supplyAsync(() ->
                    autoA.request(SCOPE, PROMPT, "v2.0", QualityAutoMeasurement.Reason.OUTSIDE_GATE));
            CompletableFuture<QualityAutoMeasurement.Result> b = CompletableFuture.supplyAsync(() ->
                    autoB.request(SCOPE, PROMPT, "v2.0", QualityAutoMeasurement.Reason.OUTSIDE_GATE));
            a.get(30, TimeUnit.SECONDS);
            b.get(30, TimeUnit.SECONDS);
        }

        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_measure where version_number = 2",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void atTheStartTheVersionsOutsideTheGateAndTheVersionInUseWithoutAMeasurementAreMeasured() {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);

        // No label: the newest Contexa version decides outside the gate.
        List<QualityAutoMeasurement.Result> newest = startOf(cases, runner, () -> null);
        assertThat(newest).singleElement().satisfies(result -> {
            assertThat(result.outcome()).isEqualTo(QualityAutoMeasurement.Outcome.QUEUED);
            assertThat(result.detail()).isEqualTo(QualityAutoMeasurement.Reason.OUTSIDE_GATE.name());
        });
        assertThat(measuredVersions()).containsExactly(1);

        // The setting names v3.0: it decides outside the gate.
        assertThat(startOf(cases, runner, () -> "v3.0")).singleElement()
                .satisfies(result -> assertThat(result.outcome()).isEqualTo(QualityAutoMeasurement.Outcome.QUEUED));
        assertThat(measuredVersions()).containsExactly(1, 3);

        // The label decides v2.0, never measured: right after an upgrade it is measured once.
        label("v2.0");
        assertThat(startOf(cases, runner, () -> null)).singleElement().satisfies(result -> {
            assertThat(result.outcome()).isEqualTo(QualityAutoMeasurement.Outcome.QUEUED);
            assertThat(result.detail()).isEqualTo(QualityAutoMeasurement.Reason.BASELINE.name());
        });
        assertThat(measuredVersions()).containsExactly(1, 2, 3);

        // A labelled version measured under other settings only is said to be stale, not measured again by itself.
        jdbc.update("delete from ctxa_prompt_version_measure where version_number = 2");
        measured(cases.latestPublished(SCOPE, PROMPT).orElseThrow(), 2, BEFORE, "model-before", "admin",
                QualityGateSourcePostgresTest::sound);
        assertThat(startOf(cases, runner, () -> null)).isEmpty();
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_measure where version_number = 2",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void aVersionFoundDecidingOutsideTheGateIsMeasuredWithoutHoldingTheDecision() throws Exception {
        PromptQualityCases cases = cases(8);
        PromptQualityMeasurements runner = measurements(cases, 0);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        QualityAutoMeasurement auto = new QualityAutoMeasurement(() -> jdbc, versions, cases, () -> runner,
                catalog(() -> "v2.0"), null, shared(), executor);
        PromptVersionResolver resolver = resolver(() -> "v2.0");
        resolver.setQualityGateSource(() -> source(cases, runner));
        resolver.setOutsideGateListener(() -> auto);

        for (int decision = 0; decision < 3; decision++) {
            assertThat(resolver.select(new PromptGovernanceResolutionContext(SCOPE, PROMPT, "SecurityDecisionStandard",
                    null, null, null, null, Map.of()), null).source())
                    .isEqualTo(PromptBundleSelectionSource.CONFIGURATION);
        }
        auto.decidesOutsideGate(PROMPT, "v3.0", PromptBundleSelectionSource.CONFIGURATION,
                QualityMeasurementState.UNMEASURABLE);
        executor.shutdown();
        assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

        assertThat(measuredVersions()).containsExactly(2);
    }

    // ----- fixtures -----

    /**
     * Cases of the default set Contexa ships, as the default set of these tests: the first of them to be stopped and the
     * first to be allowed, half and half.
     */
    private static PromptQualityCases cases(int count) {
        List<QualityCase> some = new ArrayList<>(all.cases().stream().filter(QualityCase::shouldStop)
                .limit(count / 2).toList());
        some.addAll(all.cases().stream().filter(item -> !item.shouldStop()).limit(count - count / 2).toList());
        QualityCaseSet shipped = new QualityCaseSet(all.name(), some);
        return new PromptQualityCases(() -> jdbc, JSON, false, PromptVersionAudit.none(), CLOCK, null, () -> shipped);
    }

    /** A runner of measurements that never takes its lock, so it replays nothing; a call limit of 0 sets none. */
    private PromptQualityMeasurements measurements(PromptQualityCases cases, int callLimit) {
        PromptQualityRunLine line = new PromptQualityRunLine();
        lines.add(line);
        PromptQualityMeasurements runner = new PromptQualityMeasurements(() -> jdbc, versions, cases,
                (actor, given, format, version, user, organization, scope, timeZone) -> {
                    throw new IllegalStateException("Nothing is replayed in this test");
                }, line, atMostFor -> Optional.empty(), () -> SETTINGS, () -> QualityClosingRules.DEFAULTS,
                new PromptQualityMeasurements.Settings(3, 1, 0, Duration.ZERO, callLimit, Duration.ofSeconds(60)),
                JSON, CLOCK, "server-" + opened.size());
        opened.add(runner);
        return runner;
    }

    private MeasuredQualityGateSource source(PromptQualityCases cases, PromptQualityMeasurements runner) {
        return new MeasuredQualityGateSource(() -> jdbc, versions, cases, () -> runner, null);
    }

    private QualityAutoMeasurement auto(PromptQualityCases cases, Supplier<PromptQualityMeasurements> runner,
                                        QualityMeasureLock lock, QualityShippedMeasurements shipped) {
        return new QualityAutoMeasurement(() -> jdbc, versions, cases, runner, catalog(() -> null), shipped, lock);
    }

    private List<QualityAutoMeasurement.Result> startOf(PromptQualityCases cases, PromptQualityMeasurements runner,
                                                        Supplier<String> setting) {
        return new QualityAutoMeasurement(() -> jdbc, versions, cases, () -> runner, catalog(setting), null, shared())
                .measureDecidingVersions();
    }

    private PromptVersionResolver resolver(Supplier<String> setting) {
        return new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, JSON).registrySelector(),
                versions, setting, CLOCK);
    }

    private JdbcPromptVersionCatalog catalog(Supplier<String> setting) {
        PromptVersionResolver resolver = resolver(setting);
        return new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver);
    }

    private static QualityMeasureLock shared() {
        return QualityMeasureLock.shedLock(new JdbcTemplateLockProvider(jdbc, "ctxa_shedlock"),
                QualityAutoMeasurement.LOCK_NAME, CLOCK);
    }

    private static String sound(QualityCase item) {
        return item.shouldStop() ? "BLOCK" : "ALLOW";
    }

    private long measured(PromptQualityCases.PublishedSet set, int version, String settingsHash, String model,
                          String createdBy, Function<QualityCase, String> action) {
        return measured(set, version, settingsHash, model, createdBy, action, 0);
    }

    /** A finished measurement as its runner writes it: every case of the set in three runs. */
    private long measured(PromptQualityCases.PublishedSet set, int version, String settingsHash, String model,
                          String createdBy, Function<QualityCase, String> action, int differentRun) {
        long id = measure(set, version, settingsHash, "settings=" + settingsHash + ";models=" + model,
                PromptQualityMeasurements.DONE, createdBy);
        String content = versions.find(SCOPE, PROMPT, version).orElseThrow().contentHash();
        PromptQualityCases cases = new PromptQualityCases(() -> jdbc, JSON, false, null, CLOCK, null, () -> all);
        for (QualityCase item : cases.read(set).cases().cases()) {
            for (int run = 1; run <= 3; run++) {
                String answer = differentRun == 0 || run == differentRun ? action.apply(item) : sound(item);
                jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                        + " case_content_hash, version_number, version_content_hash, settings_hash, run_number,"
                        + " first_action, final_action, cited_facts, accurate_cited_facts, answered_model, created_at)"
                        + " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 3, 3, ?, ?)", id, SCOPE, item.key(),
                        item.contentHash(), version, content, settingsHash, run, answer, answer, model,
                        Timestamp.from(CLOCK.instant()));
            }
        }
        return id;
    }

    /** A second finished measurement of the same version whose every answer is one of the first, used again. */
    private void reusing(long first, PromptQualityCases.PublishedSet set) {
        Map<String, Object> row = jdbc.queryForMap("select version_number, settings_hash, model_setting from"
                + " ctxa_prompt_version_measure where id = ?", first);
        long id = measure(set, (Integer) row.get("version_number"), (String) row.get("settings_hash"),
                (String) row.get("model_setting"), PromptQualityMeasurements.DONE, "admin");
        jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                + " case_content_hash, version_number, version_content_hash, settings_hash, run_number, first_action,"
                + " final_action, cited_facts, accurate_cited_facts, answered_model, reused_from_answer_id, created_at)"
                + " select ?, registry_scope, case_key, case_content_hash, version_number, version_content_hash,"
                + " settings_hash, run_number, first_action, final_action, cited_facts, accurate_cited_facts,"
                + " answered_model, id, created_at from ctxa_prompt_version_measure_answer where measure_id = ?", id,
                first);
    }

    private long measure(PromptQualityCases.PublishedSet set, int version, String settingsHash, String modelSetting,
                         String status, String createdBy) {
        String content = versions.find(SCOPE, PROMPT, version).orElseThrow().contentHash();
        return jdbc.queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key,"
                + " version_number, version_content_hash, case_set_id, case_set_version, repeats, settings_hash,"
                + " settings, model_setting, closing_rules, status, planned_answers, reusable_answers,"
                + " expected_min_calls, expected_max_calls, call_limit, created_by, created_at) values (?, ?, ?, ?, ?,"
                + " ?, 3, ?, '{}', ?, 'test', ?, 24, 0, 24, 96, 0, ?, ?) returning id", Long.class, SCOPE, PROMPT,
                version, content, set.id(), set.version(), settingsHash, modelSetting, status, createdBy,
                Timestamp.from(CLOCK.instant().plusMillis(jdbc.queryForObject("select count(*) from"
                        + " ctxa_prompt_version_measure", Long.class))));
    }

    private static QualityShippedMeasurements shippedOf(String content, String setVersion, String settingsHash,
                                                        List<QualityCase> items) throws Exception {
        StringBuilder answers = new StringBuilder();
        for (QualityCase item : items) {
            for (int run = 1; run <= 3; run++) {
                answers.append(answers.isEmpty() ? "" : ",").append("{\"caseKey\":\"").append(item.key())
                        .append("\",\"run\":").append(run).append(",\"firstAction\":\"").append(sound(item))
                        .append("\",\"finalAction\":\"").append(sound(item))
                        .append("\",\"citedFacts\":3,\"accurateCitedFacts\":3}");
            }
        }
        String document = "{\"format\":1,\"measurements\":[{\"prompt\":\"" + PROMPT + "\",\"release\":\"test\","
                + "\"versionContentHash\":\"" + content + "\",\"caseSetVersion\":\"" + setVersion + "\","
                + "\"settingsHash\":\"" + settingsHash + "\",\"modelSetting\":\"settings=" + settingsHash
                + ";models=model-a\",\"repeats\":3,\"measuredAt\":\"2026-11-30T00:00:00Z\",\"answers\":[" + answers
                + "]}]}";
        return QualityShippedMeasurements.read(new ByteArrayInputStream(document.getBytes(StandardCharsets.UTF_8)));
    }

    private static List<Integer> measuredVersions() {
        return jdbc.queryForList("select distinct version_number from ctxa_prompt_version_measure order by 1",
                Integer.class);
    }

    private static void label(String version) {
        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'ACTIVE', updated_at = ? where"
                + " prompt_version = ?", Timestamp.from(Instant.now()), version);
    }
}
