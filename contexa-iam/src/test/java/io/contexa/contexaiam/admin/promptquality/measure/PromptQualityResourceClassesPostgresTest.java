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
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityActionBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityAnswer;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseRationale;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseResource;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateReading;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSide;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurement;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityNoise;
import io.contexa.contexacore.std.components.prompt.quality.QualityRate;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceClassComparison;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceClassScore;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceCoverage;
import io.contexa.contexacore.std.components.prompt.quality.QualityScorer;
import io.contexa.contexacore.std.components.prompt.quality.QualityVerdict;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseResources;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseSealedForm;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
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
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Quality P46 on a database with the schema of a new installation: the coverage of the cases of a scope by resource
 * class beside the decisions of the hourly table of the console (its tenant's, every tenant's for the platform, the
 * hours of the period, decisions only), the class of a kept case read from its stored input, the metrics of a
 * measurement class by class on both bases, and the comparison of two versions class by class on what the gate reads.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityResourceClassesPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String TENANT = "tenant-a";
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final Instant NOW = Instant.parse("2026-11-22T12:00:00Z");
    private static final Instant FROM = Instant.parse("2026-11-01T00:00:00Z");
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;
    private static QualityCaseSet all;

    private final List<PromptQualityMeasurements> opened = new CopyOnWriteArrayList<>();
    private final List<PromptQualityRunLine> lines = new CopyOnWriteArrayList<>();

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
    void nothingKept() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_case_cause, ctxa_prompt_version_measure_prompt,"
                + " ctxa_prompt_version_measure_answer, ctxa_prompt_version_measure, ctxa_prompt_version_case_set_member,"
                + " ctxa_prompt_version_case_set, ctxa_prompt_version_case_change, ctxa_prompt_version_case,"
                + " ctxa_prompt_version_part, ctxa_prompt_version, ctxa_shedlock, ctxa_zt_stats_hourly CASCADE");
    }

    @AfterEach
    void closeAll() {
        opened.forEach(PromptQualityMeasurements::close);
        lines.forEach(PromptQualityRunLine::close);
    }

    // ----- fixtures -----

    private static PromptQualityCases cases(boolean twoPerson) {
        return new PromptQualityCases(() -> jdbc, JSON, twoPerson, PromptVersionAudit.none(),
                Clock.fixed(NOW, ZoneOffset.UTC), null, () -> all);
    }

    private static PromptQualityResourceClasses classes(PromptQualityCases cases,
                                                        PromptQualityMeasurements measurements,
                                                        QualityGateSource gate) {
        return new PromptQualityResourceClasses(() -> jdbc, cases, () -> measurements, () -> gate,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static void hour(String at, String tenant, String resourceClass, String action, long decisions) {
        jdbc.update("insert into ctxa_zt_stats_hourly (bucket_start, tenant_id, resource_class, final_action,"
                + " decision_count) values (?, ?, ?, ?, ?)", Timestamp.from(Instant.parse(at)), tenant, resourceClass,
                action, decisions);
    }

    /** A copy of a case of the default set that must be allowed, on another resource of another class. */
    private static QualityCaseInput onAnotherResource(String resourceClass, String resource) {
        QualityCase source = all.cases().stream().filter(item -> !item.shouldStop()).findFirst().orElseThrow();
        ObjectNode context = source.input().canonicalContext().deepCopy();
        ((ObjectNode) context.path("resource")).put("resourceClass", resourceClass);
        ObjectNode facts = source.input().requestFacts().deepCopy();
        facts.put("resourceId", resource).put("protectableResourceId", resource)
                .put("protectableResourceUrl", "/api/notices/{noticeKey}");
        QualityCaseInput input = source.input();
        return new QualityCaseInput(context, facts, input.authState(), input.baselineSnapshot(), input.ragResults(),
                input.pastDeniedDecisions(), input.personalBaseline(), input.organizationBaseline());
    }

    private static QualityCaseExpectation allowed() {
        return new QualityCaseExpectation(EnumSet.of(QualityAction.ALLOW, QualityAction.CHALLENGE), null,
                QualityCaseClass.NORMAL, QualityCaseKind.NORMAL_WORK,
                new QualityCaseRationale("정상 업무", "Normal work"), List.of());
    }

    private static String sourceKey() {
        return all.cases().stream().filter(item -> !item.shouldStop()).findFirst().orElseThrow().key();
    }

    // ----- the tests -----

    /** The cases of the scope by class beside the decisions of its tenant in the period. */
    @Test
    void theCoverageOfAScopeStandsBesideTheDecisionsOfItsTenant() {
        PromptQualityCases cases = cases(true);
        // A confirmed case on a NORMAL resource, and one on a PUBLIC resource that waits: only the first is counted.
        PromptQualityCases.Kept normal = cases.copy(TENANT, PROMPT, sourceKey(),
                onAnotherResource("NORMAL", "Ops#readNotice"), allowed(), QualityCaseGrade.ORDINARY, "alice");
        cases.confirm(TENANT, PROMPT, normal.key(), "bob");
        cases.copy(TENANT, PROMPT, sourceKey(), onAnotherResource("PUBLIC", "Ops#readNews"), allowed(),
                QualityCaseGrade.ORDINARY, "alice");
        // The decisions: the tenant's in the period by class; a row of no decision, an hour before the period and
        // another tenant's are not counted.
        hour("2026-11-10T08:00:00Z", TENANT, "CRITICAL", "ALLOW", 10);
        hour("2026-11-10T09:00:00Z", TENANT, "CRITICAL", "BLOCK", 5);
        hour("2026-11-10T09:00:00Z", TENANT, "NORMAL", "ALLOW", 400);
        hour("2026-11-11T09:00:00Z", TENANT, "", "ALLOW", 7);
        hour("2026-11-11T09:00:00Z", TENANT, "SENSITIVE", "NO_DECISION", 3);
        hour("2026-10-31T23:00:00Z", TENANT, "CRITICAL", "ALLOW", 1000);
        hour("2026-11-12T09:00:00Z", "tenant-b", "SENSITIVE", "CHALLENGE", 20);
        hour("2026-11-12T10:00:00Z", "tenant-b", "PUBLIC", "ALLOW", 2);

        PromptQualityResourceClasses classes = classes(cases, null, null);
        PromptQualityResourceClasses.Coverage read = classes.coverage(TENANT, PROMPT, null, FROM,
                NOW.plus(Duration.ofDays(30)));

        assertThat(read.tenant()).isEqualTo(TENANT);
        assertThat(read.to()).as("a later end is now").isEqualTo(NOW);
        assertThat(read.caseSetId()).isNull();
        QualityResourceCoverage coverage = read.coverage();
        assertThat(coverage.cases()).isEqualTo(71);
        assertThat(coverage.operationDecisions()).isEqualTo(422);
        assertThat(coverage.minimumRoots()).isEqualTo(5);
        assertThat(coverage.classes()).containsExactly(
                new QualityResourceCoverage.ClassRow("CRITICAL", 31, 22, 9, 12, 5, 4, 15,
                        QualityResourceCoverage.Gap.NONE),
                new QualityResourceCoverage.ClassRow("SENSITIVE", 39, 33, 6, 13, 5, 3, 0,
                        QualityResourceCoverage.Gap.NONE),
                new QualityResourceCoverage.ClassRow("NORMAL", 1, 0, 1, 0, 1, 1, 400,
                        QualityResourceCoverage.Gap.FEW_CASES),
                new QualityResourceCoverage.ClassRow("PUBLIC", 0, 0, 0, 0, 0, 0, 0, QualityResourceCoverage.Gap.NONE),
                new QualityResourceCoverage.ClassRow(QualityCaseResource.UNCLASSIFIED, 0, 0, 0, 0, 0, 0, 7,
                        QualityResourceCoverage.Gap.NO_CASES));
        assertThat(coverage.resources()).isEqualTo(7);
        assertThat(coverage.topResources()).hasSize(7);
        assertThat(coverage.topResources()).filteredOn(row -> row.resource().equals("Ops#readNotice"))
                .singleElement().satisfies(row -> {
                    assertThat(row.resourceClasses()).containsExactly("NORMAL");
                    assertThat(row.urlTemplate()).isEqualTo("/api/notices/{noticeKey}");
                });

        // The platform scope counts every tenant's decisions; no case is kept there.
        QualityResourceCoverage platform = classes.coverage(null, PROMPT, null, FROM, NOW).coverage();
        assertThat(platform.cases()).isEqualTo(70);
        assertThat(platform.operationDecisions()).isEqualTo(444);
        assertThat(platform.find("SENSITIVE").orElseThrow().operationDecisions()).isEqualTo(20);
        assertThat(platform.find("PUBLIC").orElseThrow().gap()).isEqualTo(QualityResourceCoverage.Gap.NO_CASES);
        assertThat(platform.find("NORMAL").orElseThrow().gap()).isEqualTo(QualityResourceCoverage.Gap.NO_CASES);
        assertThat(platform.gaps()).extracting(QualityResourceCoverage.ClassRow::resourceClass)
                .containsExactly("NORMAL", "PUBLIC", QualityCaseResource.UNCLASSIFIED);
        // The hourly table holds what the operation decided: the classes counted add up to its sum.
        Long sum = jdbc.queryForObject("select sum(decision_count) from ctxa_zt_stats_hourly where bucket_start >= ?"
                + " and bucket_start < ? and final_action <> 'NO_DECISION'", Long.class, Timestamp.from(FROM),
                Timestamp.from(NOW));
        assertThat(platform.operationDecisions()).isEqualTo(sum);
    }

    /** A published set is read as it was published, and only a set of the scope. */
    @Test
    void aPublishedSetIsReadAsPublishedAndTheRequestIsChecked() {
        PromptQualityCases cases = cases(false);
        cases.copy(TENANT, PROMPT, sourceKey(), onAnotherResource("NORMAL", "Ops#readNotice"), allowed(),
                QualityCaseGrade.ORDINARY, "alice");
        PromptQualityCases.PublishedSet set = cases.publish(TENANT, PROMPT, "alice");
        PromptQualityCases.PublishedSet platformSet = cases.publishDefault(null, PROMPT, "alice");
        PromptQualityResourceClasses classes = classes(cases, null, null);

        PromptQualityResourceClasses.Coverage read = classes.coverage(TENANT, PROMPT, set.id(), null, null);

        assertThat(read.caseSetVersion()).isEqualTo(set.version());
        assertThat(read.from()).isEqualTo(NOW.minus(PromptQualityResourceClasses.DEFAULT_PERIOD));
        assertThat(read.coverage().cases()).isEqualTo(71);
        assertThat(read.coverage().find("NORMAL").orElseThrow().cases()).isEqualTo(1);
        assertThatThrownBy(() -> classes.coverage(TENANT, PROMPT, platformSet.id(), null, null))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.NOT_FOUND));
        assertThatThrownBy(() -> classes.coverage(TENANT, "cortex.other", null, null, null))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.PROMPT));
        assertThatThrownBy(() -> classes.coverage(TENANT, PROMPT, null, NOW, NOW.minusSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> classes.coverage(TENANT, PROMPT, null, NOW.minus(Duration.ofDays(401)), NOW))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** A measurement that lets the critical threats through: worse there alone, none for the classes no case has. */
    @Test
    void aMeasurementIsScoredClassByClassOnBothBases() throws Exception {
        PromptVersionService versions = new PromptVersionService(() -> jdbc,
                SecurityDecisionPromptDocument.productReleases(), Map.of(), PromptVersionAudit.none(),
                Clock.systemUTC());
        versions.registerProducts(null);
        PromptQualityCases cases = cases(false);
        cases.publish(null, PROMPT, "admin");
        Map<String, QualityCase> byKey = new HashMap<>();
        all.cases().forEach(item -> byKey.put(item.key(), item));
        PromptQualityMeasurements.Replayer replayer = (actor, given, format, version, user, organization) -> {
            QualityCase item = byKey.get(keyOf(given));
            boolean critical = "CRITICAL".equals(QualityCaseResources.of(item).resourceClass());
            String action = !item.shouldStop() || critical ? "ALLOW" : "BLOCK";
            return PromptQualityMeasurementsPostgresTest.answered(given, action,
                    SealedDecisionReplayService.Outcome.ANSWERED, List.of());
        };
        PromptQualityRunLine line = new PromptQualityRunLine();
        lines.add(line);
        PromptQualityMeasurements measurements = new PromptQualityMeasurements(() -> jdbc, versions, cases, replayer,
                line, QualityMeasureLock.local(), () -> Map.of("layer1.model", "stand-in-model"),
                () -> QualityClosingRules.DEFAULTS, new PromptQualityMeasurements.Settings(1, 2, 0, Duration.ZERO,
                3000, Duration.ofMillis(200)), JSON, Clock.systemUTC(), "server-a");
        opened.add(measurements);
        long id = measurements.start(null, PROMPT, 1, null, 1, "admin");
        await(measurements, id);

        PromptQualityResourceClasses.MeasurementClasses read = classes(cases, measurements, null).measurement(id)
                .orElseThrow();

        assertThat(read.missingCases()).isEmpty();
        assertThat(read.firstAnswer()).extracting(QualityResourceClassScore::resourceClass)
                .containsExactly("CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC");
        QualityRate criticalMiss = read.firstAnswer().get(0).score().rate(QualityMetric.MISS);
        assertThat(criticalMiss.events()).isEqualTo(22);
        assertThat(criticalMiss.trials()).isEqualTo(22);
        assertThat(criticalMiss.roots()).isEqualTo(12);
        assertThat(criticalMiss.lower()).isGreaterThan(0.7);
        assertThat(criticalMiss.upper()).isEqualTo(1.0);
        QualityRate sensitiveMiss = read.firstAnswer().get(1).score().rate(QualityMetric.MISS);
        assertThat(sensitiveMiss.events()).isZero();
        assertThat(sensitiveMiss.trials()).isEqualTo(33);
        assertThat(sensitiveMiss.roots()).isEqualTo(13);
        assertThat(sensitiveMiss.lower()).isZero();
        assertThat(read.firstAnswer().get(1).score().rate(QualityMetric.FALSE_STOP).events()).isZero();
        assertThat(read.firstAnswer().get(1).score().rate(QualityMetric.FALSE_STOP).trials()).isEqualTo(6);
        assertThat(read.firstAnswer().get(2).scored()).isFalse();
        assertThat(read.firstAnswer().get(3).scored()).isFalse();
        // The whole set averages the two: 22 misses of 55.
        QualityRate whole = measurements.result(id).orElseThrow().firstAnswer().rate(QualityMetric.MISS);
        assertThat(whole.events()).isEqualTo(22);
        assertThat(whole.trials()).isEqualTo(55);
        // No closing rule changed an action, so the final actions are scored the same.
        assertThat(read.finalAction().get(0).score().rate(QualityMetric.MISS)).isEqualTo(criticalMiss);
        assertThat(classes(cases, measurements, null).measurement(id + 1000)).isEmpty();
        assertThat(classes(cases, null, null).measurement(id)).isEmpty();
    }

    /** Two versions class by class on the measurements the gate reads, and nothing when it reads none. */
    @Test
    void twoVersionsAreComparedClassByClassOnWhatTheGateReads() {
        PromptQualityCases cases = cases(false);
        List<QualityAnswer> before = new ArrayList<>();
        List<QualityAnswer> after = new ArrayList<>();
        for (QualityCase item : all.cases()) {
            boolean critical = "CRITICAL".equals(QualityCaseResources.of(item).resourceClass());
            QualityAction right = item.shouldStop() ? QualityAction.BLOCK : QualityAction.ALLOW;
            before.add(answer(item.key(), right));
            after.add(answer(item.key(), item.shouldStop() && critical ? QualityAction.ALLOW : right));
        }
        QualityMeasurement current = new QualityMeasurement("v1.0", "model", "set", 1, before);
        QualityMeasurement candidate = new QualityMeasurement("v2.0", "model", "set", 1, after);
        QualityNoise noise = new QualityNoise(Map.of(QualityMetric.MISS, 0.0));
        String[] asked = new String[4];
        QualityGateSource gate = (scope, prompt, version, inUse) -> {
            asked[0] = scope;
            asked[1] = prompt;
            asked[2] = version;
            asked[3] = inUse;
            return QualityGateReading.measured(new QualityGateInput(all.cases(), current, candidate, noise, null,
                    null));
        };

        PromptQualityResourceClasses.ComparisonClasses compared = classes(cases, null, gate)
                .comparison(null, PROMPT, "v2.0", "v1.0");

        assertThat(asked).containsExactly(PromptVersionService.PLATFORM_SCOPE, PROMPT, "v2.0", "v1.0");
        assertThat(compared.state()).isEqualTo(QualityMeasurementState.MEASURED);
        assertThat(compared.basis()).isEqualTo(QualityActionBasis.FIRST_ANSWER);
        assertThat(compared.classes()).extracting(QualityResourceClassComparison::resourceClass)
                .containsExactly("CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC");
        QualityResourceClassComparison critical = compared.classes().get(0);
        assertThat(critical.comparison(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.WORSE);
        assertThat(critical.comparison(QualityMetric.MISS).worseRoots()).isEqualTo(12);
        assertThat(critical.changes().newlyMissed()).hasSize(22);
        assertThat(critical.changedCases()).isEqualTo(22);
        QualityResourceClassComparison sensitive = compared.classes().get(1);
        assertThat(sensitive.comparison(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.SAME);
        assertThat(sensitive.changedCases()).isZero();
        assertThat(compared.classes().get(2).compared()).isFalse();
        // The classes add up to what the whole comparison pairs.
        assertThat(compared.classes().stream().filter(QualityResourceClassComparison::compared)
                .mapToInt(row -> row.comparison(QualityMetric.MISS).pairedCases()).sum())
                .isEqualTo(QualityScorer.score(all.cases(), before, QualityActionBasis.FIRST_ANSWER)
                        .rate(QualityMetric.MISS).cases());

        PromptQualityResourceClasses.ComparisonClasses none = classes(cases, null, null)
                .comparison(TENANT, PROMPT, "v2.0", "v1.0");
        assertThat(none.state()).isEqualTo(QualityMeasurementState.UNMEASURABLE);
        assertThat(none.detail()).isEqualTo(QualityGateSource.NO_SOURCE);
        assertThat(none.classes()).isEmpty();
        QualityGateSource candidateOnly = (scope, prompt, version, inUse) -> QualityGateReading.missing(
                Set.of(QualityGateSide.CURRENT),
                new QualityGateInput(all.cases(), null, candidate, noise, null, null));
        assertThat(classes(cases, null, candidateOnly).comparison(TENANT, PROMPT, "v2.0", "v1.0").classes())
                .isEmpty();
    }

    private static QualityAnswer answer(String key, QualityAction action) {
        return new QualityAnswer(key, 1, action, null, false, false, 0, 0, 1000L, 100, false, null);
    }

    private static String keyOf(SealedEvidencePackage given) {
        return given.getPackageId().substring(QualityCaseSealedForm.PACKAGE_ID_PREFIX.length());
    }

    private static void await(PromptQualityMeasurements measurements, long id) throws InterruptedException {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (System.nanoTime() < until) {
            String status = measurements.find(id).orElseThrow().status();
            if (PromptQualityMeasurements.DONE.equals(status)) {
                return;
            }
            assertThat(status).isNotEqualTo(PromptQualityMeasurements.FAILED);
            Thread.sleep(50);
        }
        throw new AssertionError("Measurement " + id + " is " + measurements.find(id).orElseThrow().status());
    }
}
