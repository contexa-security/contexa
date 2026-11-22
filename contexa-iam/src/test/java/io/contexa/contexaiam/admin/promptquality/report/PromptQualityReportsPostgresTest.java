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
package io.contexa.contexaiam.admin.promptquality.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateCondition;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateEvaluator;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateFinding;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateMode;
import io.contexa.contexacore.std.components.prompt.quality.QualityGatePolicy;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateResult;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityRate;
import io.contexa.contexacore.std.components.prompt.quality.QualityShippedMeasurements;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.causes.PromptQualityCauses;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.admin.promptquality.measure.MeasuredQualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityRunLine;
import io.contexa.contexaiam.admin.promptquality.measure.QualityAutoMeasurement;
import io.contexa.contexaiam.admin.promptquality.measure.QualityMeasureLock;
import io.contexa.contexaiam.admin.promptquality.measure.QualityModelSetting;
import io.contexa.contexaiam.admin.promptquality.measure.QualityScheduledMeasurement;
import io.contexa.contexaiam.admin.promptquality.status.PromptQualityStatus;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustDecisionRecords;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.assertj.core.groups.Tuple;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Quality plan 3.7, 3.2 on a database with the schema of a new installation: the quality report holds what its sources
 * hold, section by section; a part without data says none and why instead of zero; the scope and the period bound
 * what it reads; and no value a case, a decision or an administrator's text holds of a person comes out as it is.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityReportsPostgresTest {

    private static final String SCOPE = PromptVersionService.PLATFORM_SCOPE;
    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String TENANT = "tenant-b";
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-11-22T12:30:00Z");
    private static final Instant FROM = Instant.parse("2026-11-01T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Map<String, String> SETTINGS = Map.of("layer1.model", "model-a", "timeZone", "UTC");

    /** What a case, a decision or a text holds of the person, which no file of the bundle may hold. */
    private static final String USER = "kim.subject";
    private static final String OTHER_USER = "lee.other";
    private static final String ADDRESS = "203.0.113.77";
    private static final String ADDRESS_V6 = "2001:db8:85a3::8a2e:370:7334";
    private static final String MAIL = "kim.private@example.com";
    private static final String NETWORK = "198.51.100.0/24";
    private static final String DEVICE = "Galaxy-S24-Kim";
    private static final String PATH = "/payroll/kim-secret-path";
    private static final List<String> PERSONAL = List.of(USER, OTHER_USER, ADDRESS, ADDRESS_V6, MAIL, NETWORK,
            "198.51.100", DEVICE, PATH, "kim-secret");

    private static QualityCaseSet all;
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

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
                + " ctxa_zt_review_queue, ctxa_sealed_evidence_package, ctxa_zt_decision_outcome,"
                + " ctxa_ai_security_decision_observation, ctxa_prompt_inspection_result, ctxa_audit_log,"
                + " ctxa_prompt_governance_release_workflow, ctxa_prompt_governance_rollback_execution CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), TARGETS,
                PromptVersionAudit.none(), CLOCK);
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
     * Every section holds what its source holds: the declared measurement's rates are the runner's, the conditions
     * one measurement decides are the evaluator's, the comparison with v1.0 is the gate's, the set's composition is
     * that of its cases, the operation metrics are the sums of the hourly table in the period, the overturned decisions
     * are the outcomes of the period with their decisions, and the history is the audit log, the workflow and the
     * rollbacks of the period in the scope.
     */
    @Test
    void everySectionHoldsWhatItsSourceHolds() throws Exception {
        PromptQualityMeasurements runner = measurements();
        Fixture fixture = everything();

        PromptQualityReports.Export export = reports(runner).export(new PromptQualityReports.Request(null, FROM, null,
                "auditor"));
        QualityReport report = export.report();

        assertThat(export.fileName()).isEqualTo("prompt-quality-report-2026-11-22_123000.zip");
        assertThat(report.format()).isEqualTo(QualityReport.FORMAT);
        assertThat(report.header().from()).isEqualTo(FROM.toString());
        assertThat(report.header().to()).isEqualTo(NOW.toString());
        assertThat(report.header().decisionTenant()).isNull();
        assertThat(report.header().answers()).containsExactly(Map.entry("ACCURACY_DECLARATION", "accuracy"),
                Map.entry("POST_MARKET_MONITORING", "monitoring"), Map.entry("OVERTURNED_DECISIONS", "reversals"));
        assertThat(report.header().gate()).isEqualTo(new QualityReport.Gate("WARN", 0.05, 0.05, 200, 300));
        assertThat(report.header().modelSetting().settingsHash()).isEqualTo(QualityModelSetting.hash(SETTINGS));

        // 1. the declaration: the rates of the runner's result, on both bases
        QualityReport.Accuracy accuracy = report.accuracy();
        assertThat(accuracy.missing()).isNull();
        assertThat(accuracy.version()).isEqualTo("v2.0");
        assertThat(accuracy.state()).isEqualTo("MEASURED");
        PromptQualityMeasurements.Result result = runner.result(fixture.inUse()).orElseThrow();
        assertThat(accuracy.declared().measureId()).isEqualTo(fixture.inUse());
        for (QualityMetric metric : QualityMetric.values()) {
            QualityRate first = result.firstAnswer().rate(metric);
            PromptQualityStatus.Rate kept = accuracy.declared().firstAnswer().rates().get(metric.name());
            assertThat(List.of(kept.events(), kept.trials(), (long) kept.roots())).as(metric.name())
                    .containsExactly(first.events(), first.trials(), (long) first.roots());
            QualityRate last = result.finalAction().rate(metric);
            assertThat(accuracy.declared().finalAction().rates().get(metric.name()).events()).isEqualTo(last.events());
        }
        PromptQualityStatus.Rate miss = accuracy.declared().firstAnswer().rates().get("MISS");
        assertThat(List.of(miss.events(), miss.trials())).containsExactly(3L, 15L);
        assertThat(miss.lower()).isNotNull().isLessThan(0.2);
        assertThat(miss.upper()).isNotNull().isGreaterThan(0.2);
        assertThat(accuracy.sufficiency()).isEqualTo(new QualityReport.Sufficiency(
                result.firstAnswer().rate(QualityMetric.MISS).roots(), 200,
                result.firstAnswer().rate(QualityMetric.FALSE_STOP).roots(), 300, false));
        QualityGateResult evaluated = QualityGateEvaluator.evaluate(new QualityGateInput(
                cases.read(cases.latestPublished(SCOPE, PROMPT).orElseThrow()).cases().cases(), null,
                result.measurement(), null, QualityGateSettings.defaults(),
                versions.find(SCOPE, PROMPT, 2).orElseThrow().createdAt()));
        assertThat(accuracy.alone()).extracting(QualityReport.Finding::condition, QualityReport.Finding::status,
                QualityReport.Finding::caseKeys).containsExactly(
                findingOf(evaluated, "MUST_CATCH_NEVER_ALLOWED"), findingOf(evaluated, "MUST_NOT_BLOCK_NEVER_BLOCKED"),
                findingOf(evaluated, "NOT_WORSE_ON_LATER_CASES_ONLY"));
        // the comparison with the version it replaced, as the gate compares them
        assertThat(accuracy.comparisons()).extracting(QualityReport.Comparison::against).containsExactly("v1.0");
        QualityReport.Comparison comparison = accuracy.comparisons().get(0);
        assertThat(comparison.state()).isEqualTo("MEASURED");
        QualityReport.MetricComparison missed = comparison.metrics().stream()
                .filter(metric -> metric.metric().equals("MISS")).findFirst().orElseThrow();
        assertThat(missed.inUseValue()).isEqualTo(0.2);
        assertThat(missed.beforeValue()).isEqualTo(0.0);
        assertThat(missed.noiseWidth()).as("v1.0 measured twice with the same answers").isEqualTo(0.0);
        assertThat(missed.verdict()).isEqualTo("UNDECIDABLE");
        assertThat(comparison.metrics().stream().filter(metric -> metric.metric().equals("FALSE_STOP")).findFirst()
                .orElseThrow().verdict()).isEqualTo("SAME");
        assertThat(comparison.changes().newlyMissed()).containsExactly(fixture.missedKey());
        // the measurements finished in the period: both, the newest first, the one before the period not
        assertThat(accuracy.measurements()).extracting(QualityReport.MeasurementRow::id)
                .containsExactly(fixture.inUse(), fixture.before());
        assertThat(accuracy.measurements().get(1).firstAnswer().rates().get("MISS").events()).isZero();

        // 2. the case sets: the composition of the cases of the set as they read now
        QualityReport.CaseSets caseSets = report.caseSets();
        assertThat(caseSets.missing()).isNull();
        assertThat(caseSets.inventory()).isEqualTo(new QualityReport.Inventory(1, 0, 0, 0, false,
                cases.defaultSet().version(), 8));
        assertThat(caseSets.sets()).hasSize(1);
        QualityReport.SetRow set = caseSets.sets().get(0);
        PromptQualityCases.ReadSet read = cases.read(cases.latestPublished(SCOPE, PROMPT).orElseThrow());
        assertThat(set.reasons()).as("published now, at the end of the period, which is not in it")
                .containsExactly("LATEST", "MEASURED");
        assertThat(set.caseCount()).isEqualTo(9).isEqualTo(read.set().caseCount());
        assertThat(set.readable()).isEqualTo(read.cases().cases().size());
        assertThat(set.byGrade().values().stream().mapToInt(Integer::intValue).sum()).isEqualTo(9);
        assertThat(set.byOrigin()).containsEntry("CONTEXA", 8).containsEntry("CUSTOMER", 1);
        assertThat(set.stopRoots()).isEqualTo(read.cases().cases().stream().filter(QualityCase::shouldStop)
                .map(QualityCase::rootKey).distinct().count());
        assertThat(set.allowRoots()).isEqualTo(read.cases().cases().stream().filter(item -> !item.shouldStop())
                .map(QualityCase::rootKey).distinct().count());

        // 3. the monitoring: the sums of the hourly table in the period, version by version
        QualityReport.Monitoring monitoring = report.monitoring();
        assertThat(monitoring.missing()).isNull();
        assertThat(monitoring.versions()).extracting(QualityReport.VersionOperation::version,
                QualityReport.VersionOperation::inUse, QualityReport.VersionOperation::decisions)
                .as("every tenant in the platform scope, the hour before the period and no decision left out")
                .containsExactly(tuple("v2.0", true, 160L), tuple("v1.0", false, 112L));
        PromptQualityStatus.Rate stopped = monitoring.versions().get(0).rates().get("STOPPED");
        assertThat(List.of(stopped.events(), stopped.trials())).containsExactly(30L, 160L);
        assertThat(stopped.value()).isEqualTo(0.1875);
        assertThat(stopped.lower()).isLessThan(0.1875);
        assertThat(stopped.upper()).isGreaterThan(0.1875);
        PromptQualityStatus.Rate released = monitoring.versions().get(0).rates().get("BLOCK_RELEASE");
        assertThat(List.of(released.events(), released.trials())).containsExactly(2L, 10L);
        assertThat(monitoring.change().previousVersion()).isEqualTo("v1.0");
        assertThat(monitoring.measurementCauses().missing()).isNull();
        assertThat(monitoring.measurementCauses().measureId()).isEqualTo(fixture.inUse());
        assertThat(monitoring.measurementCauses().counts().stream().mapToInt(QualityReport.CauseCount::count).sum())
                .isEqualTo(monitoring.measurementCauses().listed()).isEqualTo(3);
        assertThat(monitoring.decisionCauses().listed()).isEqualTo(1);

        // 4. the overturned decisions of the period, with the decision's own action and version
        QualityReport.Reversals reversals = report.reversals();
        assertThat(reversals.missing()).isNull();
        assertThat(reversals.kinds()).extracting(QualityReport.KindSummary::kind, QualityReport.KindSummary::decisions)
                .as("every tenant; a block released twice once; the release before the period not")
                .containsExactly(tuple("ADMIN_RELEASED", 2), tuple("EVALUATED_INVALID", 1),
                        tuple("ALLOWED_BREACH_CONFIRMED", 1));
        assertThat(reversals.kinds().get(0).byAction()).containsExactly(Map.entry("BLOCK", 2));
        assertThat(reversals.kinds().get(0).byVersion()).containsExactly(Map.entry("v2.0", 2));
        assertThat(reversals.kinds().get(1).byReason()).containsExactly(Map.entry("FACTS_WRONG", 1));
        assertThat(reversals.kinds().get(2).byAction()).containsExactly(Map.entry("ALLOW", 1));
        assertThat(List.of(reversals.invalidShare().events(), reversals.invalidShare().trials()))
                .as("the decision rated wrong and then right counts as right").containsExactly(1L, 2L);
        assertThat(reversals.entries()).extracting(QualityReport.ReversedDecision::kind,
                QualityReport.ReversedDecision::observationId).containsExactly(
                tuple("ALLOWED_BREACH_CONFIRMED", "d-allow"), tuple("EVALUATED_INVALID", "d-wrong"),
                tuple("ADMIN_RELEASED", "d-block"), tuple("ADMIN_RELEASED", "d-tenant"));
        assertThat(reversals.entries().get(2).action()).isEqualTo("BLOCK");
        assertThat(reversals.entries().get(2).version()).isEqualTo("v2.0");
        assertThat(reversals.entries().get(2).reviewer()).isEqualTo("admin-b");
        assertThat(reversals.entries()).extracting(QualityReport.ReversedDecision::noted)
                .as("the notes are left out, their being there is kept").containsExactly(true, true, true, false);
        String pseudonym = reversals.entries().get(2).subject();
        assertThat(pseudonym).startsWith(QualityReportMasking.SUBJECT_PREFIX);
        assertThat(reversals.entries().get(0).subject()).as("the same person, the same pseudonym").isEqualTo(pseudonym);
        assertThat(reversals.entries().get(1).subject()).isNotEqualTo(pseudonym);

        // 5. the history of the period in the scope
        QualityReport.History history = report.history();
        assertThat(history.audit()).extracting(QualityReport.AuditEntry::action).containsExactly(
                PromptVersionAudit.QUALITY_GATE_OVERRIDDEN, PromptVersionAudit.CASE_SET_PUBLISHED);
        assertThat(history.auditByAction()).containsExactly(Map.entry(PromptVersionAudit.CASE_SET_PUBLISHED, 1),
                Map.entry(PromptVersionAudit.QUALITY_GATE_OVERRIDDEN, 1));
        assertThat(history.transitions()).extracting(QualityReport.Transition::version,
                QualityReport.Transition::overridden).containsExactly(tuple("v2.0", true), tuple("v2.0", false));
        assertThat(history.overrides()).isEqualTo(1);
        assertThat(history.rollbacks()).extracting(QualityReport.Rollback::executionKey).containsExactly("rb-1");
        assertThat(history.audit().get(0).reason()).contains(pseudonym).contains(QualityReportMasking.ADDRESS_MARK);

        // 6. the masking, and the bundle
        assertThat(report.masking().subjects()).isEqualTo(2);
        assertThat(report.masking().scrubbedTexts()).isGreaterThanOrEqualTo(4);
        Map<String, String> files = unzip(export.bytes());
        assertThat(files.keySet()).containsExactly("report.json", "report-ko.md", "report-en.md");
        JsonNode json = JSON.readTree(files.get("report.json"));
        assertThat(json.path("accuracy").path("declared").path("firstAnswer").path("rates").path("MISS")
                .path("events").asLong()).isEqualTo(3);
        assertThat(files.get("report-ko.md")).contains("# 프롬프트 품질 보고서").contains("3/15 = 20.0%");
        assertThat(files.get("report-en.md")).contains("# Prompt quality report").contains("3/15 = 20.0%")
                .contains("EU AI Act, Article 15");
    }

    /** No value of a person comes out as it is: not in the JSON, not in either readable file. */
    @Test
    void noValueOfAPersonLeavesThePrompt() throws Exception {
        PromptQualityMeasurements runner = measurements();
        everything();
        assertThat(jdbc.queryForObject("select case_input from ctxa_prompt_version_case", String.class))
                .as("the case keeps them").contains(USER, ADDRESS, NETWORK, DEVICE, PATH);

        PromptQualityReports.Export export = reports(runner).export(new PromptQualityReports.Request(null, FROM, null,
                "auditor"));

        Map<String, String> files = unzip(export.bytes());
        for (Map.Entry<String, String> file : files.entrySet()) {
            for (String personal : PERSONAL) {
                assertThat(file.getValue()).as(file.getKey() + " holds " + personal).doesNotContain(personal);
            }
        }
        assertThat(files.get("report.json")).contains(QualityReportMasking.SUBJECT_PREFIX)
                .contains(QualityReportMasking.EMAIL_MARK).contains(QualityReportMasking.ADDRESS_MARK);
        assertThat(files.get("report-en.md")).contains("auditor").contains("admin-b").as("the administrators")
                .contains("admin-a");
        // two reports name the same person by two pseudonyms
        String first = export.report().reversals().entries().get(2).subject();
        String second = reports(runner).report(new PromptQualityReports.Request(null, FROM, null, "auditor"))
                .reversals().entries().get(2).subject();
        assertThat(first).isNotEqualTo(second);
    }

    /** The scope bounds the versions, the cases and the history; its tenant bounds the decisions. */
    @Test
    void theScopeAndItsTenantBoundWhatIsRead() throws Exception {
        PromptQualityMeasurements runner = measurements();
        everything();

        QualityReport other = reports(runner).report(new PromptQualityReports.Request(TENANT, FROM, null, "auditor"));

        assertThat(other.header().scope()).isEqualTo(TENANT);
        assertThat(other.header().decisionTenant()).isEqualTo(TENANT);
        assertThat(other.caseSets().missing()).isEqualTo("NO_CASE_SET");
        assertThat(other.accuracy().measurements()).isEmpty();
        assertThat(other.history().audit()).extracting(QualityReport.AuditEntry::action)
                .containsExactly(PromptVersionAudit.USED_FOR_DECISIONS);
        assertThat(other.history().transitions()).isEmpty();
        assertThat(other.reversals().kinds()).extracting(QualityReport.KindSummary::decisions)
                .containsExactly(1, 0, 0);
        assertThat(other.reversals().entries()).extracting(QualityReport.ReversedDecision::observationId)
                .containsExactly("d-tenant");
        assertThat(other.monitoring().versions()).extracting(QualityReport.VersionOperation::version,
                QualityReport.VersionOperation::decisions).containsExactly(tuple("v2.0", 40L));
    }

    /** The period bounds what happened; the version in use and its latest measurement are those of now. */
    @Test
    void thePeriodBoundsWhatHappened() throws Exception {
        PromptQualityMeasurements runner = measurements();
        Fixture fixture = everything();

        QualityReport early = reports(runner).report(new PromptQualityReports.Request(null,
                Instant.parse("2026-09-01T00:00:00Z"), Instant.parse("2026-09-30T00:00:00Z"), "auditor"));

        assertThat(early.accuracy().declared().measureId()).isEqualTo(fixture.inUse());
        assertThat(early.accuracy().measurements()).isEmpty();
        assertThat(early.caseSets().sets()).extracting(QualityReport.SetRow::reasons)
                .containsExactly(List.of("LATEST", "MEASURED"));
        assertThat(early.monitoring().missing()).isEqualTo("NO_DECISIONS_IN_PERIOD");
        assertThat(early.reversals().missing()).isEqualTo("NO_REVERSALS_IN_PERIOD");
        assertThat(early.history().audit()).isEmpty();
        assertThat(early.history().transitions()).isEmpty();
        assertThat(early.history().rollbacks()).isEmpty();

        PromptQualityReports reports = reports(runner);
        assertThatThrownBy(() -> reports.report(new PromptQualityReports.Request(null, NOW, FROM, "auditor")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> reports.report(new PromptQualityReports.Request(null, NOW.minus(Duration.ofDays(401)),
                NOW, "auditor"))).isInstanceOf(IllegalArgumentException.class);
        assertThat(reports.report(new PromptQualityReports.Request(null, null, null, "auditor")).header().from())
                .isEqualTo(NOW.minus(Duration.ofDays(90)).toString());
    }

    /**
     * Without data every part says none and why, never zero: no version, no case set, no measurement, no decisions,
     * no reversals; and a rate without a denominator has no value. Without a runner nothing can be measured.
     */
    @Test
    void withoutDataEveryPartSaysNoneAndWhy() throws Exception {
        PromptQualityMeasurements runner = measurements();

        QualityReport empty = reports(runner).report(new PromptQualityReports.Request(null, FROM, null, "auditor"));

        assertThat(empty.accuracy().missing()).isEqualTo("NO_VERSION_IN_USE");
        assertThat(empty.accuracy().declared()).isNull();
        assertThat(empty.caseSets().missing()).isEqualTo("NO_CASE_SET");
        assertThat(empty.monitoring().missing()).isEqualTo("NO_DECISIONS_IN_PERIOD");
        assertThat(empty.monitoring().measurementCauses().missing()).isEqualTo("NO_MEASUREMENT");
        assertThat(empty.reversals().missing()).isEqualTo("NO_REVERSALS_IN_PERIOD");
        assertThat(empty.reversals().invalidShare().value()).isNull();
        assertThat(empty.reversals().invalidShare().lower()).isNull();

        versions.registerProducts(null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Payroll\nsystem:\n"
                + "  - key: how-to-judge\n    text: |\n      1. Weigh the payroll roster first.\n",
                PromptVersionRecord.SCREEN, null, "admin", null);
        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'ACTIVE', updated_at = ? where"
                + " prompt_version = 'v2.0'", Timestamp.from(NOW));
        assertThat(reports(runner).report(new PromptQualityReports.Request(null, FROM, null, "auditor")).accuracy()
                .missing()).isEqualTo("NO_CASE_SET");
        cases.publishDefault(SCOPE, PROMPT, "admin");
        QualityReport unmeasured = reports(runner).report(new PromptQualityReports.Request(null, FROM, null,
                "auditor"));
        assertThat(unmeasured.accuracy().missing()).isEqualTo("NO_MEASUREMENT");
        assertThat(unmeasured.accuracy().state()).isEqualTo("MISSING");
        QualityReport unmeasurable = reports(null).report(new PromptQualityReports.Request(null, FROM, null,
                "auditor"));
        assertThat(unmeasurable.accuracy().missing()).isEqualTo("UNMEASURABLE");
        assertThat(unmeasurable.header().measurable()).isFalse();
        assertThat(unmeasurable.header().modelSetting()).isNull();

        Map<String, String> files = unzip(reports(runner).export(new PromptQualityReports.Request(null, FROM, null,
                "auditor")).bytes());
        assertThat(files.get("report-en.md")).contains("None: no decision was made in the period")
                .contains("none (no denominator)");
        assertThat(files.get("report-ko.md")).contains("없음: 기간 안에 내린 판정이 없다");
    }

    /** Every text the readable files name is in the English and the Korean bundle, and nowhere twice. */
    @Test
    void theTextsOfTheReportAreInBothBundles() throws IOException {
        Set<String> english = reportKeys("contexa/i18n/messages.properties");
        Set<String> korean = reportKeys("contexa/i18n/messages_ko.properties");

        assertThat(english).hasSizeGreaterThan(200).isEqualTo(korean);
    }

    // ----- fixtures -----

    private record Fixture(long inUse, long before, String missedKey) {
    }

    /**
     * v2.0 in use, measured in the period on the published set of the default cases and a customer case of a person,
     * missing one case that must be stopped; v1.0 measured the same way without a miss; the hours of both versions in
     * the period and one hour before it; overturned decisions in the period, one before it, one of another tenant; the
     * audit log, the workflow and a rollback in the period and outside it.
     */
    private Fixture everything() throws Exception {
        versions.registerProducts(null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Payroll of " + USER + "\nsystem:\n"
                + "  - key: how-to-judge\n    text: |\n      1. Weigh the payroll roster first.\n",
                PromptVersionRecord.SCREEN, null, "admin-a", null);
        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'ACTIVE', updated_at = ? where"
                + " prompt_version = 'v2.0'", Timestamp.from(NOW));
        QualityCase source = cases.defaultSet().cases().stream().filter(QualityCase::shouldStop).findFirst()
                .orElseThrow();
        cases.copy(SCOPE, PROMPT, source.key(), personal(source.input()), source.expectation(),
                QualityCaseGrade.ORDINARY, "admin-a");
        PromptQualityCases.PublishedSet set = cases.publish(SCOPE, PROMPT, "admin-a");
        String missedKey = cases.read(set).cases().cases().stream().filter(QualityCase::shouldStop).findFirst()
                .orElseThrow().key();
        long inUse = measured(set, 2, Instant.parse("2026-11-20T10:00:00Z"),
                item -> item.key().equals(missedKey) ? "ALLOW" : sound(item));
        long before = measured(set, 1, Instant.parse("2026-11-10T10:00:00Z"), PromptQualityReportsPostgresTest::sound);
        measured(set, 1, Instant.parse("2026-10-10T10:00:00Z"), PromptQualityReportsPostgresTest::sound);

        hour("v1.0", "2026-11-14T10:00:00Z", "ALLOW", "MODEL", 80, 0, 0, 0, 0, 4, "");
        hour("v1.0", "2026-11-14T10:00:00Z", "CHALLENGE", "MODEL", 15, 12, 0, 0, 0, 0, "");
        hour("v1.0", "2026-11-14T10:00:00Z", "BLOCK", "MODEL", 5, 0, 1, 3, 1, 0, "");
        hour("v1.0", "2026-11-14T10:00:00Z", "ALLOW", "MODEL_LESS", 2, 0, 0, 0, 0, 0, "");
        hour("v1.0", "2026-11-15T05:00:00Z", "ALLOW", "MODEL", 10, 0, 0, 0, 0, 0, "");
        hour("v1.0", "2026-10-15T05:00:00Z", "ALLOW", "MODEL", 999, 0, 0, 0, 0, 0, "");
        hour("v2.0", "2026-11-15T06:00:00Z", "ALLOW", "MODEL", 90, 0, 0, 0, 0, 2, "");
        hour("v2.0", "2026-11-18T09:00:00Z", "CHALLENGE", "MODEL", 20, 18, 0, 0, 0, 0, "");
        hour("v2.0", "2026-11-18T09:00:00Z", "BLOCK", "MODEL", 10, 0, 2, 5, 0, 0, "");
        hour("v2.0", "2026-11-18T09:00:00Z", "NO_DECISION", "", 9, 0, 0, 0, 0, 0, "");
        hour("v2.0", "2026-11-18T09:00:00Z", "ALLOW", "MODEL", 40, 0, 0, 0, 0, 0, TENANT);

        decision("d-block", USER, "", "BLOCK", "v2.0", "2026-11-18T09:10:00Z");
        decision("d-wrong", OTHER_USER, "", "CHALLENGE", "v2.0", "2026-11-18T09:20:00Z");
        decision("d-right", OTHER_USER, "", "BLOCK", "v2.0", "2026-11-18T09:30:00Z");
        decision("d-allow", USER, "", "ALLOW", "v2.0", "2026-11-18T09:40:00Z");
        decision("d-tenant", OTHER_USER, TENANT, "BLOCK", "v2.0", "2026-11-18T09:50:00Z");
        outcome("d-block", USER, "", ZeroTrustDecisionOutcomes.Kind.ADMIN_RELEASED, null, "admin-b",
                "released for " + USER + " at " + ADDRESS, "2026-11-19T10:00:00Z");
        outcome("d-block", USER, "", ZeroTrustDecisionOutcomes.Kind.ADMIN_RELEASED, null, "admin-b", null,
                "2026-11-19T11:00:00Z");
        outcome("d-wrong", OTHER_USER, "", ZeroTrustDecisionOutcomes.Kind.EVALUATED_INVALID, "FACTS_WRONG", "admin-b",
                "mail " + MAIL + " says " + OTHER_USER + " was travelling", "2026-11-19T12:00:00Z");
        outcome("d-right", OTHER_USER, "", ZeroTrustDecisionOutcomes.Kind.EVALUATED_INVALID, "OTHER", "admin-b", null,
                "2026-11-19T12:10:00Z");
        outcome("d-right", OTHER_USER, "", ZeroTrustDecisionOutcomes.Kind.EVALUATED_VALID, null, "admin-a", null,
                "2026-11-19T12:20:00Z");
        outcome("d-allow", USER, "", ZeroTrustDecisionOutcomes.Kind.ALLOWED_BREACH_CONFIRMED, null, "admin-b",
                "the device " + DEVICE + " from " + ADDRESS_V6 + " was stolen", "2026-11-20T08:00:00Z");
        outcome("d-allow", USER, "", ZeroTrustDecisionOutcomes.Kind.ADMIN_RELEASED, null, "admin-b", null,
                "2026-10-20T08:00:00Z");
        outcome("d-tenant", OTHER_USER, TENANT, ZeroTrustDecisionOutcomes.Kind.ADMIN_RELEASED, null, "admin-b", null,
                "2026-11-19T10:00:00Z");

        audit(SCOPE, PromptVersionAudit.QUALITY_GATE_OVERRIDDEN, PROMPT + "@v2.0", "admin-a",
                "verdict BLOCKED: " + USER + " asked from " + ADDRESS, "2026-11-20T09:00:00Z");
        audit(SCOPE, PromptVersionAudit.CASE_SET_PUBLISHED, PROMPT + "@" + set.version(), "admin-a", "9 cases",
                "2026-11-20T08:00:00Z");
        audit(SCOPE, PromptVersionAudit.USED_FOR_DECISIONS, PROMPT + "@v1.0", "admin-a", "before the period",
                "2026-10-20T08:00:00Z");
        audit(TENANT, PromptVersionAudit.USED_FOR_DECISIONS, PROMPT + "@v1.0", "admin-a", "other scope",
                "2026-11-20T08:00:00Z");
        audit(SCOPE, "ZERO_TRUST_SOMETHING", PROMPT + "@v2.0", "admin-a", "not a version action",
                "2026-11-20T08:00:00Z");
        transition("v2.0", "QUALITY_GATE_OVERRIDDEN", "QUALITY_GATE_OVERRIDDEN (measurement=MEASURED,"
                + " conditions=[MISS_NOT_INCREASED]): urgent fix for " + USER, "2026-11-20T09:00:00Z");
        transition("v2.0", "APPROVED", "canary", "2026-11-19T09:00:00Z");
        transition("v1.0", "APPROVED", "before the period", "2026-10-19T09:00:00Z");
        jdbc.update("insert into ctxa_prompt_governance_rollback_execution (execution_key, registry_scope, prompt_key,"
                + " from_version, to_version, actor, reason, emergency, status, executed_at) values ('rb-1', ?, ?,"
                + " 'v2.0', 'v1.0', 'admin-a', ?, true, 'APPROVED', ?)", SCOPE, PROMPT, "rollback asked by " + MAIL
                + " from " + ADDRESS_V6,
                Timestamp.from(Instant.parse("2026-11-21T09:00:00Z")));
        return new Fixture(inUse, before, missedKey);
    }

    /** The input of the case with the person's identifier, address, path and baseline in it. */
    private static QualityCaseInput personal(QualityCaseInput input) {
        ObjectNode facts = input.requestFacts().isObject() ? ((ObjectNode) input.requestFacts()).deepCopy()
                : JSON.createObjectNode();
        facts.put("userId", USER);
        facts.put("clientIp", ADDRESS);
        facts.put("requestPath", PATH);
        ObjectNode baseline = JSON.createObjectNode();
        baseline.putArray("usualNetworks").add(NETWORK);
        baseline.putArray("devices").add(DEVICE);
        return new QualityCaseInput(input.canonicalContext(), facts, input.authState(), input.baselineSnapshot(),
                input.ragResults(), input.pastDeniedDecisions(), baseline, input.organizationBaseline());
    }

    private static Tuple findingOf(QualityGateResult result, String condition) {
        QualityGateFinding finding = result.finding(QualityGateCondition.valueOf(condition));
        return tuple(condition, finding.status().name(), finding.caseKeys());
    }

    private static void hour(String version, String at, String action, String source, long decisions, long passed,
                             long released, long valid, long invalid, long retried, String tenant) {
        jdbc.update("INSERT INTO ctxa_zt_stats_hourly (bucket_start, tenant_id, final_action, decision_source,"
                + " prompt_bundle_version, decision_count, challenge_passed_count, admin_released_count,"
                + " evaluated_valid_count, evaluated_invalid_count, retried_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                + " ?)", Timestamp.from(Instant.parse(at)), tenant, action, source, version, decisions, passed,
                released, valid, invalid, retried);
    }

    private static void decision(String id, String user, String tenant, String action, String version, String at) {
        jdbc.update("insert into ctxa_ai_security_decision_observation (observation_id, request_id, tenant_id, user_id,"
                + " final_action, proposed_action, prompt_bundle_version, decision_source, success, attempt_kind,"
                + " created_at) values (?, ?, ?, ?, ?, ?, ?, 'MODEL', true, 'FIRST', ?)", id, "request-" + id,
                tenant.isEmpty() ? null : tenant, user, action, action, version, Timestamp.from(Instant.parse(at)));
    }

    private static void outcome(String observation, String user, String tenant, ZeroTrustDecisionOutcomes.Kind kind,
                                String reason, String actor, String note, String at) {
        Instant moment = Instant.parse(at);
        jdbc.update("insert into ctxa_zt_decision_outcome (outcome_id, observation_id, request_id, user_id, tenant_id,"
                + " outcome_kind, evaluation_reason, actor, note, occurred_at, created_at) values (?, ?, ?, ?, ?, ?, ?,"
                + " ?, ?, ?, ?)", "outcome-" + observation + "-" + kind + "-" + moment.toEpochMilli(), observation,
                "request-" + observation, user, tenant.isEmpty() ? null : tenant, kind.name(), reason, actor, note,
                Timestamp.from(moment), Timestamp.from(moment));
    }

    private static void audit(String scope, String action, String resource, String actor, String reason, String at) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("scope", scope);
        details.put("detail", reason);
        String written;
        try {
            written = JSON.writeValueAsString(details);
        }
        catch (Exception unwritable) {
            throw new IllegalStateException(unwritable);
        }
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, action, decision,"
                + " reason, details, event_category, client_ip) values (?, ?, ?, ?, 'RECORDED', ?, ?,"
                + " 'PROMPT_VERSION_CHANGED', ?)", Timestamp.from(Instant.parse(at)), actor, resource, action, reason,
                written, ADDRESS);
    }

    private static void transition(String version, String gate, String rationale, String at) {
        jdbc.update("insert into ctxa_prompt_governance_release_workflow (registry_scope, prompt_key, prompt_version,"
                + " current_release_status, target_release_status, workflow_state, gate_state, approval_channel,"
                + " actor_name, rationale, created_at) values (?, ?, ?, 'DRAFT', 'ACTIVE', 'APPROVED_AND_APPLIED', ?,"
                + " 'CONSOLE', 'admin-a', ?, ?)", SCOPE, PROMPT, version, gate, rationale,
                Timestamp.from(Instant.parse(at)));
    }

    private PromptQualityReports reports(PromptQualityMeasurements runner) {
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
        PromptQualityStatus status = new PromptQualityStatus(versions, catalog(), cases, () -> runner, () -> scheduled,
                () -> console, () -> records);
        PromptQualityCauses causes = new PromptQualityCauses(() -> jdbc, cases, JSON, () -> 90_000L, CLOCK);
        QualityGatePolicy gate = new QualityGatePolicy(new MeasuredQualityGateSource(() -> jdbc, versions, cases,
                () -> runner, QualityShippedMeasurements.none()), QualityGateMode.WARN, QualityGateSettings.defaults());
        return new PromptQualityReports(() -> jdbc, versions, cases, status, () -> runner, () -> causes,
                () -> console, gate, strictMessages(), JSON, CLOCK);
    }

    /** The bundles as Contexa ships them, a missing text an error instead of its key. */
    private static ResourceBundleMessageSource strictMessages() {
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasenames("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setFallbackToSystemLocale(false);
        messages.setUseCodeAsDefaultMessage(false);
        return messages;
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
                (actor, given, format, version, user, organization) -> {
                    throw new IllegalStateException("Nothing is replayed in this test");
                }, line, atMostFor -> Optional.empty(), () -> SETTINGS, () -> QualityClosingRules.DEFAULTS,
                new PromptQualityMeasurements.Settings(3, 1, 0, Duration.ZERO, 0, Duration.ofSeconds(60)), JSON,
                CLOCK, "server-" + opened.size());
        opened.add(runner);
        return runner;
    }

    private static String sound(QualityCase item) {
        return item.shouldStop() ? "BLOCK" : "ALLOW";
    }

    /** A finished measurement of the version under the test's settings: every case of the set in three runs. */
    private long measured(PromptQualityCases.PublishedSet set, int version, Instant finishedAt,
                          Function<QualityCase, String> action) {
        String content = versions.find(SCOPE, PROMPT, version).orElseThrow().contentHash();
        String hash = QualityModelSetting.hash(SETTINGS);
        String written;
        try {
            written = JSON.writeValueAsString(SETTINGS);
        }
        catch (Exception unwritable) {
            throw new IllegalStateException(unwritable);
        }
        List<QualityCase> items = cases.read(set).cases().cases();
        Long id = jdbc.queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key,"
                + " version_number, version_content_hash, case_set_id, case_set_version, repeats, settings_hash,"
                + " settings, model_setting, closing_rules, status, planned_answers, reusable_answers,"
                + " expected_min_calls, expected_max_calls, call_limit, created_by, created_at, finished_at)"
                + " values (?, ?, ?, ?, ?, ?, 3, ?, ?, ?, 'test', 'DONE', ?, 0, ?, ?, 0, 'admin-a', ?, ?) returning id",
                Long.class, SCOPE, PROMPT, version, content, set.id(), set.version(), hash, written,
                "settings=" + hash + ";models=model-a", items.size() * 3, items.size() * 3, items.size() * 12,
                Timestamp.from(finishedAt), Timestamp.from(finishedAt));
        for (QualityCase item : items) {
            for (int run = 1; run <= 3; run++) {
                String answer = action.apply(item);
                jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                        + " case_content_hash, version_number, version_content_hash, settings_hash, run_number,"
                        + " first_action, final_action, cited_facts, accurate_cited_facts, decision_ms, answered_model,"
                        + " created_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 3, 3, 7000, 'model-a', ?)", id, SCOPE,
                        item.key(), item.contentHash(), version, content, hash, run, answer, answer,
                        Timestamp.from(finishedAt));
            }
        }
        return id;
    }

    private static Map<String, String> unzip(byte[] bytes) throws IOException {
        Map<String, String> files = new LinkedHashMap<>();
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                files.put(entry.getName(), new String(zip.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
        return files;
    }

    private static Set<String> reportKeys(String path) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return properties.stringPropertyNames().stream().filter(key -> key.startsWith("pqa.report."))
                .collect(Collectors.toCollection(TreeSet::new));
    }
}
