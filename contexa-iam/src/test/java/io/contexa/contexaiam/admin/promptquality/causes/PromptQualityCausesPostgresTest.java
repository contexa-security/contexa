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
package io.contexa.contexaiam.admin.promptquality.causes;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionCitationCheck;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityCause;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseCheck;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseClassifier;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseFix;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityRunLine;
import io.contexa.contexaiam.admin.promptquality.measure.QualityMeasureLock;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
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
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Quality plan 3.5 on a database with the schema of a new installation: the wrong answers of a done measurement are
 * put down to their causes, once the measurement is done and again whenever they are read, writing nothing when the
 * rule comes to the same; the decisions an administrator rated inadequate are put down to theirs, by their tenant, and
 * again once the evidence audit inspected a seal; an administrator's correction keeps who, when and what it replaced,
 * and classifying again never overwrites it. No model is asked.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityCausesPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String SCOPE = PromptVersionService.PLATFORM_SCOPE;
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final long LIMIT = 90_000L;
    private static final List<String> SHIPPED = List.of("A1", "S04", "S10", "INS-S03", "S01");
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;
    private static List<QualityCase> shipped;

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
        Map<String, QualityCase> all = QualityCaseSetReader.contexaDefault().cases().stream()
                .collect(Collectors.toMap(QualityCase::key, item -> item));
        shipped = SHIPPED.stream().map(all::get).toList();
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    @BeforeEach
    void anEmptyStore() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_case_cause, ctxa_prompt_version_measure_prompt,"
                + " ctxa_prompt_version_measure_answer, ctxa_prompt_version_measure, ctxa_prompt_version_case_set_member,"
                + " ctxa_prompt_version_case_set, ctxa_prompt_version_case_change, ctxa_prompt_version_case,"
                + " ctxa_prompt_version_part, ctxa_prompt_version, ctxa_zt_decision_outcome,"
                + " ctxa_ai_security_decision_observation, ctxa_prompt_inspection_result, ctxa_sealed_evidence_package"
                + " CASCADE");
        QualityCaseSet set = new QualityCaseSet(QualityCaseSetReader.contexaDefault().name(), shipped);
        cases = new PromptQualityCases(() -> jdbc, JSON, false, PromptVersionAudit.none(), Clock.systemUTC(), null,
                () -> set);
    }

    // ----- fixtures -----

    private PromptQualityCauses causes(long limit) {
        return new PromptQualityCauses(() -> jdbc, cases, JSON, () -> limit, Clock.systemUTC());
    }

    private static QualityCase shippedCase(String key) {
        return shipped.stream().filter(item -> item.key().equals(key)).findFirst().orElseThrow();
    }

    private static long measure(PromptQualityCases.PublishedSet set, String status, int repeats) {
        Long id = jdbc.queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key,"
                + " version_number, version_content_hash, case_set_id, case_set_version, repeats, settings_hash,"
                + " settings, closing_rules, status, planned_answers, reusable_answers, expected_min_calls,"
                + " expected_max_calls, call_limit, created_by, created_at) values (?, ?, 1, 'version-hash', ?, ?, ?,"
                + " 'settings-hash', '{}', 'rules', ?, 0, 0, 0, 0, 0, 'admin', ?) returning id", Long.class, SCOPE,
                PROMPT, set.id(), set.version(), repeats, status, Timestamp.from(Instant.now()));
        return id != null ? id : -1;
    }

    /** An answer of the measurement: its actions, its citations (cited, on a line, named by the check), its call. */
    private static void answer(long measure, String key, int run, String first, String model, String last, int cited,
                               int present, int flagged, long callMillis, boolean failed) {
        jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                + " case_content_hash, version_number, version_content_hash, settings_hash, run_number, outcome,"
                + " first_action, model_action, final_action, citation_state, cited_facts, present_facts, flagged_facts,"
                + " accurate_cited_facts, citation_findings, model_calls, decision_ms, measurement_failed,"
                + " failure_reason, created_at) values (?, ?, ?, ?, 1, 'version-hash', 'settings-hash', ?, ?, ?, ?, ?,"
                + " ?, ?, ?, ?, ?, '[]', ?, ?, ?, ?, ?)", measure, SCOPE, key, shippedCase(key).contentHash(), run,
                failed ? "INFRASTRUCTURE_FAILURE" : "ANSWERED", failed ? null : first, failed ? null : model,
                failed ? null : last, failed ? null : "CHECKED", failed ? 0 : cited, failed ? null : present,
                failed ? null : flagged, failed ? 0 : present - flagged,
                "[{\"pass\":1,\"callMs\":" + callMillis + ",\"gateWaitMs\":0,\"timeoutMs\":720000,\"failed\":false}]",
                callMillis + 100, failed, failed ? "INFRASTRUCTURE_FAILURE: busy" : null, Timestamp.from(Instant.now()));
    }

    /**
     * A done measurement of three runs: A1 allows a threat in two runs of three (unstable), S04 allows it in every run
     * with the right citations (judgement), S10 deferred rightly and the closing rules ended it in ALLOW (engine
     * changed), INS-S03 allows it citing a fact the prompt does not say (grounding; K189 corrected its input, so its
     * deciding on-call record is no longer unknown to the prompt), S01 blocks normal work after a call of 95 seconds
     * (format and model) and once could not be measured.
     */
    private long aDoneMeasurement() {
        PromptQualityCases.PublishedSet set = cases.publish(SCOPE, PROMPT, "admin");
        long id = measure(set, PromptQualityMeasurements.DONE, 3);
        answer(id, "A1", 1, "ALLOW", "ALLOW", "ALLOW", 3, 3, 0, 6_000L, false);
        answer(id, "A1", 2, "BLOCK", "BLOCK", "BLOCK", 3, 3, 0, 6_000L, false);
        answer(id, "A1", 3, "ALLOW", "ALLOW", "ALLOW", 3, 3, 0, 6_000L, false);
        for (int run = 1; run <= 3; run++) {
            answer(id, "S04", run, "ALLOW", "ALLOW", "ALLOW", 3, 3, 0, 6_000L, false);
            answer(id, "INS-S03", run, "ALLOW", "ALLOW", "ALLOW", 3, 3, 1, 6_000L, false);
        }
        answer(id, "S10", 1, "ESCALATE", "ESCALATE", "ALLOW", 2, 2, 0, 6_000L, false);
        answer(id, "S10", 2, "BLOCK", "BLOCK", "BLOCK", 2, 2, 0, 6_000L, false);
        answer(id, "S10", 3, "BLOCK", "BLOCK", "BLOCK", 2, 2, 0, 6_000L, false);
        answer(id, "S01", 1, "BLOCK", "BLOCK", "BLOCK", 2, 2, 0, 95_000L, false);
        answer(id, "S01", 2, "ALLOW", "ALLOW", "ALLOW", 2, 2, 0, 6_000L, false);
        answer(id, "S01", 3, null, null, null, 0, 0, 0, 0L, true);
        return id;
    }

    private static List<Map<String, Object>> rows() {
        return jdbc.queryForList("select id, registry_scope, measure_id, case_key, run_number, observation_id,"
                + " category, rule_category, rule_basis, wrong_basis, classified_by, classified_at, corrected_by,"
                + " corrected_at, previous_category from ctxa_prompt_version_case_cause order by id");
    }

    private static Map<String, QualityCause> categories(PromptQualityCauses.Summary summary) {
        return summary.causes().stream().collect(Collectors.toMap(cause -> cause.caseKey() != null
                ? cause.caseKey() + "#" + cause.run() : cause.observationId(), PromptQualityCauses.Cause::category));
    }

    private static int count(PromptQualityCauses.Summary summary, QualityCause cause) {
        return summary.counts().stream().filter(found -> found.cause() == cause).findFirst().orElseThrow().count();
    }

    // ----- measurements -----

    @Test
    void theWrongAnswersOfADoneMeasurementArePutDownToTheirCausesAndClassifyingAgainWritesNothing() {
        long id = aDoneMeasurement();
        PromptQualityCauses causes = causes(LIMIT);

        PromptQualityCauses.Summary summary = causes.ofMeasurement(id).orElseThrow();

        assertThat(categories(summary)).containsExactlyInAnyOrderEntriesOf(Map.ofEntries(
                Map.entry("A1#1", QualityCause.UNSTABLE), Map.entry("A1#3", QualityCause.UNSTABLE),
                Map.entry("S04#1", QualityCause.JUDGEMENT_ERROR), Map.entry("S04#2", QualityCause.JUDGEMENT_ERROR),
                Map.entry("S04#3", QualityCause.JUDGEMENT_ERROR), Map.entry("S10#1", QualityCause.ENGINE_CHANGED),
                Map.entry("INS-S03#1", QualityCause.GROUNDING_ERROR),
                Map.entry("INS-S03#2", QualityCause.GROUNDING_ERROR),
                Map.entry("INS-S03#3", QualityCause.GROUNDING_ERROR),
                Map.entry("S01#1", QualityCause.FORMAT_AND_MODEL)));
        assertThat(summary.counts()).extracting(PromptQualityCauses.Count::cause).containsExactly(QualityCause.values());
        assertThat(count(summary, QualityCause.JUDGEMENT_ERROR)).isEqualTo(3);
        assertThat(count(summary, QualityCause.INPUT_ERROR)).isZero();
        assertThat(count(summary, QualityCause.UNCLASSIFIED)).isZero();
        // Input shortage is not computed for the answers of the original cases, which list no deciding fact (A1,
        // S04, S10, S01); a measured answer is never put down to an input error, so that one is always computed.
        assertThat(summary.counts().stream().filter(found -> found.cause() == QualityCause.INPUT_SHORTAGE)
                .findFirst().orElseThrow().notComputed()).isEqualTo(7);
        assertThat(summary.counts().stream().filter(found -> found.cause() == QualityCause.INPUT_ERROR)
                .findFirst().orElseThrow().notComputed()).isZero();
        // The cases a new version of the prompt fixes, to show beside the editor.
        assertThat(summary.forNewVersion()).extracting(PromptQualityCauses.Cause::caseKey)
                .containsExactly("S04", "S04", "S04");
        assertThat(summary.forNewVersion()).allSatisfy(cause -> assertThat(cause.fix())
                .isEqualTo(QualityCauseFix.PROMPT_VERSION));

        PromptQualityCauses.Cause engine = summary.causes().stream()
                .filter(cause -> "S10".equals(cause.caseKey())).findFirst().orElseThrow();
        assertThat(engine.basis()).isEqualTo(QualityCauseBasis.FINAL);
        assertThat(engine.source()).isEqualTo(PromptQualityCauses.Source.MEASUREMENT);
        assertThat(engine.actions()).containsEntry("first", "ESCALATE").containsEntry("final", "ALLOW")
                .containsEntry("allowed", List.of("CHALLENGE", "ESCALATE", "BLOCK"));
        assertThat(engine.checks()).extracting(QualityCauseCheck::cause).containsExactlyElementsOf(QualityCause.RULED);
        assertThat(engine.classifiedBy()).isEqualTo(PromptQualityCauses.RULES);
        PromptQualityCauses.Cause slow = summary.causes().stream()
                .filter(cause -> "S01".equals(cause.caseKey())).findFirst().orElseThrow();
        assertThat(slow.checks().get(0).details()).containsExactly("reason=OVER_TIME_LIMIT", "call1Ms=95000",
                "limitMs=90000");
        // The input shortage is read against the facts the prompt names unknown: the variant's deciding facts are
        // all known since K189, so it is clear and the grounding decides.
        PromptQualityCauses.Cause grounded = summary.causes().stream()
                .filter(cause -> "INS-S03".equals(cause.caseKey())).findFirst().orElseThrow();
        assertThat(grounded.checks().get(3).cause()).isEqualTo(QualityCause.INPUT_SHORTAGE);
        assertThat(grounded.checks().get(3).state()).isEqualTo(QualityCauseCheck.State.CLEAR);
        assertThat(grounded.checks().get(3).details()).containsExactly("level=BUSINESS_AWARE", "unknown=PeerCohort");
        assertThat(grounded.fix()).isEqualTo(QualityCauseFix.PROMPT_OR_MODEL);

        List<Map<String, Object>> before = rows();
        assertThat(causes.ofMeasurement(id).orElseThrow().causes()).hasSize(10);
        assertThat(causes.classifyMeasurement(id)).isEqualTo(10);
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    void aMeasurementNotDoneIsLeftAlone() {
        PromptQualityCases.PublishedSet set = cases.publish(SCOPE, PROMPT, "admin");
        long running = measure(set, PromptQualityMeasurements.RUNNING, 1);
        answer(running, "S04", 1, "ALLOW", "ALLOW", "ALLOW", 3, 3, 0, 6_000L, false);

        assertThat(causes(LIMIT).classifyMeasurement(running)).isZero();
        assertThat(causes(LIMIT).ofMeasurement(running).orElseThrow().causes()).isEmpty();
        assertThat(causes(LIMIT).ofMeasurement(running + 1000)).isEmpty();
    }

    @Test
    void aCorrectionKeepsWhoWhenAndWhatItReplacedAndClassifyingAgainNeverOverwritesIt() {
        long id = aDoneMeasurement();
        PromptQualityCauses causes = causes(LIMIT);
        PromptQualityCauses.Summary summary = causes.ofMeasurement(id).orElseThrow();
        long judged = summary.causes().stream().filter(cause -> "S04".equals(cause.caseKey()) && cause.run() == 1)
                .findFirst().orElseThrow().id();

        PromptQualityCauses.Cause corrected = causes.correct(SCOPE, judged, QualityCause.GROUNDING_ERROR, "admin-b");
        assertThat(corrected.category()).isEqualTo(QualityCause.GROUNDING_ERROR);
        assertThat(corrected.ruleCategory()).isEqualTo(QualityCause.JUDGEMENT_ERROR);
        assertThat(corrected.previousCategory()).isEqualTo(QualityCause.JUDGEMENT_ERROR);
        assertThat(corrected.correctedBy()).isEqualTo("admin-b");
        assertThat(corrected.correctedAt()).isNotNull();
        PromptQualityCauses.Cause again = causes.correct(SCOPE, judged, QualityCause.FORMAT_AND_MODEL, "admin-c");
        assertThat(again.previousCategory()).isEqualTo(QualityCause.GROUNDING_ERROR);
        assertThat(again.correctedBy()).isEqualTo("admin-c");

        // Without the limit of the decisions the slow call is no longer over it: the rules come to another result,
        // the next cause that applies (its two runs gave two actions).
        PromptQualityCauses.Summary reclassified = causes(0).ofMeasurement(id).orElseThrow();
        Map<String, QualityCause> now = categories(reclassified);
        assertThat(now.get("S01#1")).isEqualTo(QualityCause.UNSTABLE);
        assertThat(now.get("S04#1")).isEqualTo(QualityCause.FORMAT_AND_MODEL);
        PromptQualityCauses.Cause kept = causes.find(SCOPE, judged).orElseThrow();
        assertThat(kept.ruleCategory()).isEqualTo(QualityCause.JUDGEMENT_ERROR);
        assertThat(kept.checks().get(0).reason()).isEqualTo(QualityCauseClassifier.TIME_LIMIT_UNKNOWN);
        assertThat(kept.correctedBy()).isEqualTo("admin-c");
        assertThat(kept.previousCategory()).isEqualTo(QualityCause.GROUNDING_ERROR);
        // The correction counts as the cause, and leaves the cases of a new version.
        assertThat(count(reclassified, QualityCause.FORMAT_AND_MODEL)).isEqualTo(1);
        assertThat(reclassified.forNewVersion()).extracting(PromptQualityCauses.Cause::run)
                .containsExactly(2, 3);

        assertThatThrownBy(() -> causes.correct(SCOPE, judged, QualityCause.UNCLASSIFIED, "admin-b"))
                .isInstanceOfSatisfying(PromptQualityCauses.RefusedException.class, refused -> assertThat(
                        refused.refusal()).isEqualTo(PromptQualityCauses.Refusal.CATEGORY));
        assertThatThrownBy(() -> causes.correct(SCOPE, judged, QualityCause.INPUT_ERROR, "admin-b"))
                .isInstanceOfSatisfying(PromptQualityCauses.RefusedException.class, refused -> assertThat(
                        refused.refusal()).isEqualTo(PromptQualityCauses.Refusal.DECISIONS_ONLY));
        assertThatThrownBy(() -> causes.correct("tenant-b", judged, QualityCause.UNSTABLE, "admin-b"))
                .isInstanceOfSatisfying(PromptQualityCauses.RefusedException.class, refused -> assertThat(
                        refused.refusal()).isEqualTo(PromptQualityCauses.Refusal.NOT_FOUND));
    }

    @Test
    void aMeasurementIsPutDownToItsCausesOnceItIsDone() throws Exception {
        PromptVersionService versions = new PromptVersionService(() -> jdbc,
                SecurityDecisionPromptDocument.productReleases(), Map.of(), PromptVersionAudit.none(),
                Clock.systemUTC());
        versions.registerProducts(null);
        cases.publish(SCOPE, PROMPT, "admin");
        PromptQualityCauses causes = causes(PromptQualityCauses.decisionCallLimitMillis(new TieredStrategyProperties()));
        PromptQualityRunLine line = new PromptQualityRunLine();
        // The stand-in of the replay allows every case: the threats are wrong, the normal work is right.
        PromptQualityMeasurements.Replayer allowEverything =
                (actor, given, format, version, user, organization, scope, timeZone) -> allowed(given);
        try (PromptQualityMeasurements measurements = new PromptQualityMeasurements(() -> jdbc, versions, cases,
                allowEverything, line, QualityMeasureLock.local(), () -> Map.of("layer1.model", "stand-in-model"),
                () -> QualityClosingRules.DEFAULTS, new PromptQualityMeasurements.Settings(1, 1, 0, Duration.ZERO, 0,
                Duration.ofMillis(200)), JSON, Clock.systemUTC(), "server-a")) {
            measurements.whenDone(causes::classifyMeasurement);
            long id = measurements.start(SCOPE, PROMPT, 1, null, 1, "admin");
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
            while (!PromptQualityMeasurements.DONE.equals(measurements.find(id).orElseThrow().status())
                    && System.nanoTime() < until) {
                Thread.sleep(50);
            }
            assertThat(measurements.find(id).orElseThrow().status()).isEqualTo(PromptQualityMeasurements.DONE);
            long classified = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (rows().size() < 4 && System.nanoTime() < classified) {
                Thread.sleep(50);
            }
            // Classified when done, before anything read the causes.
            assertThat(rows()).extracting(row -> row.get("case_key") + "#" + row.get("run_number"))
                    .containsExactlyInAnyOrder("A1#1", "S04#1", "S10#1", "INS-S03#1");
            assertThat(rows()).extracting(row -> row.get("classified_by")).containsOnly(PromptQualityCauses.RULES);
            assertThat(rows()).extracting(row -> row.get("wrong_basis")).containsOnly("BOTH");
        }
        finally {
            line.close();
        }
    }

    private static SealedDecisionReplayService.Result allowed(SealedEvidencePackage given) {
        return new SealedDecisionReplayService.Result(given.getCorrelationId(), "replay-1", given.getPackageId(),
                "v1.0", "ALLOW", "stand-in", List.of(), null, null, Map.of("runtimeModelId", "stand-in-model"),
                7000L, null, List.of(), SealedDecisionReplayService.Outcome.ANSWERED, "ALLOW", "the system prompt",
                "the user prompt", new SecurityDecisionCitationCheck(SecurityDecisionCitationCheck.State.CHECKED, 2, 2,
                0, 0, false, List.of()), List.of(new SealedDecisionReplayService.ModelCall(6500L, 20L, 720000L,
                false)));
    }

    // ----- decisions -----

    private static void observation(String id, String request, String tenant, String source, String cause,
                                    String proposed, String last, String level, Integer cited, Integer present,
                                    Integer flagged) {
        jdbc.update("insert into ctxa_ai_security_decision_observation (observation_id, request_id, tenant_id,"
                + " final_action, proposed_action, decision_source, decision_change_cause, llm_decision_present,"
                + " context_coverage_level, decision_summary_json, citation_check_state, citation_cited_count,"
                + " citation_present_count, citation_flagged_count, success, created_at) values (?, ?, ?, ?, ?, ?, ?,"
                + " ?, ?, ?, ?, ?, ?, ?, true, ?)", id, request, tenant, last, proposed, source, cause,
                !"MODEL_LESS".equals(source), level, "{\"unknown\":{\"OnCall\":\"NOT_INTEGRATED\"}}",
                cited != null ? "CHECKED" : null, cited, present, flagged, Timestamp.from(Instant.now()));
    }

    private static void evaluated(String observation, String request, String tenant, String kind, String reason,
                                  Instant at) {
        jdbc.update("insert into ctxa_zt_decision_outcome (outcome_id, observation_id, request_id, tenant_id,"
                + " outcome_kind, evaluation_reason, actor, occurred_at, created_at) values (?, ?, ?, ?, ?, ?, 'admin',"
                + " ?, ?)", "outcome-" + observation + "-" + kind + "-" + at.toEpochMilli(), observation, request,
                tenant, kind, reason, Timestamp.from(at), Timestamp.from(at));
    }

    private static void sealed(String packageId, String request) {
        jdbc.update("insert into ctxa_sealed_evidence_package (package_id, correlation_id, captured_at, package_hash)"
                + " values (?, ?, ?, 'hash')", packageId, request, Timestamp.from(Instant.now()));
    }

    private static void inspected(String packageId, int matched, int mismatched) {
        jdbc.update("insert into ctxa_prompt_inspection_result (package_id, inspector_version, verdict, checked_count,"
                + " mismatch_count, unverifiable_count, check_counts_json, inspection_trigger, inspected_at) values"
                + " (?, 'v1', 'MISMATCH', ?, ?, 0, ?, 'MANUAL', ?)", packageId, matched + mismatched, mismatched,
                "[{\"checkCode\":\"SEAL_INTEGRITY\",\"matched\":1,\"mismatched\":0,\"unverifiable\":0},"
                        + "{\"checkCode\":\"SOURCE_TRUTH\",\"matched\":" + matched + ",\"mismatched\":" + mismatched
                        + ",\"unverifiable\":0}]", Timestamp.from(Instant.now()));
    }

    @Test
    void theDecisionsRatedInadequateArePutDownToTheirCausesByTheirTenantAndAgainOnceASealIsInspected() {
        Instant from = Instant.now().minus(1, ChronoUnit.DAYS);
        Instant to = Instant.now().plus(1, ChronoUnit.HOURS);
        Instant at = Instant.now().minus(2, ChronoUnit.HOURS);
        observation("obs-1", "req-1", null, "MODEL", null, "ALLOW", "ALLOW", "BUSINESS_AWARE", 3, 3, 0);
        sealed("package-1", "req-1");
        observation("obs-2", "req-2", null, "MODEL_LESS", "CONTRACT_FALLBACK", null, "CHALLENGE", "BUSINESS_AWARE",
                null, null, null);
        observation("obs-3", "req-3", null, "ENGINE_CHANGED", "ESCALATE_PROTECTION", "ESCALATE", "CHALLENGE",
                "BUSINESS_AWARE", 2, 2, 0);
        observation("obs-4", "req-4", null, "MODEL", null, "ALLOW", "ALLOW", "IDENTITY_AWARE", 3, 2, 0);
        observation("obs-5", "req-5", null, "MODEL", null, "BLOCK", "BLOCK", "BUSINESS_AWARE", 3, 3, 0);
        observation("obs-6", "req-6", "tenant-b", "MODEL", null, "BLOCK", "BLOCK", "BUSINESS_AWARE", 3, 3, 1);
        observation("obs-7", "req-7", null, "MODEL", null, "ALLOW", "ALLOW", "BUSINESS_AWARE", 3, 3, 0);
        evaluated("obs-1", "req-1", null, "EVALUATED_INVALID", "MISSED_SIGNAL", at);
        evaluated("obs-2", "req-2", null, "EVALUATED_INVALID", "OVERREACTION", at.plusSeconds(1));
        evaluated("obs-3", "req-3", null, "EVALUATED_INVALID", "OVERREACTION", at.plusSeconds(2));
        evaluated("obs-4", "req-4", null, "EVALUATED_INVALID", "MISSED_SIGNAL", at.plusSeconds(3));
        // Rated inadequate, then right: not inadequate any more.
        evaluated("obs-5", "req-5", null, "EVALUATED_INVALID", "OVERREACTION", at.plusSeconds(4));
        evaluated("obs-5", "req-5", null, "EVALUATED_VALID", null, at.plusSeconds(5));
        evaluated("obs-6", "req-6", "tenant-b", "EVALUATED_INVALID", "FACTS_WRONG", at.plusSeconds(6));
        // Before the period.
        evaluated("obs-7", "req-7", null, "EVALUATED_INVALID", "OTHER", from.minusSeconds(60));
        // An evaluation whose decision record is gone.
        evaluated(null, "req-gone", null, "EVALUATED_INVALID", "OTHER", at.plusSeconds(7));
        PromptQualityCauses causes = causes(LIMIT);

        PromptQualityCauses.Summary summary = causes.ofDecisions(SCOPE, from, to);

        assertThat(summary.causes()).extracting(PromptQualityCauses.Cause::observationId)
                .containsExactly("obs-1", "obs-2", "obs-3", "obs-4", "obs-6");
        assertThat(categories(summary)).containsExactlyInAnyOrderEntriesOf(Map.of(
                "obs-1", QualityCause.JUDGEMENT_ERROR, "obs-2", QualityCause.FORMAT_AND_MODEL,
                "obs-3", QualityCause.ENGINE_CHANGED, "obs-4", QualityCause.INPUT_SHORTAGE,
                "obs-6", QualityCause.GROUNDING_ERROR));
        assertThat(summary.withoutRecord()).isEqualTo(1);
        assertThat(summary.forNewVersion()).extracting(PromptQualityCauses.Cause::observationId)
                .containsExactly("obs-1");
        PromptQualityCauses.Cause first = summary.causes().get(0);
        assertThat(first.source()).isEqualTo(PromptQualityCauses.Source.DECISION);
        assertThat(first.requestId()).isEqualTo("req-1");
        assertThat(first.basis()).isNull();
        assertThat(first.scope()).isEqualTo(SCOPE);
        assertThat(first.checks().get(2).reason()).isEqualTo(QualityCauseClassifier.NOT_INSPECTED);
        assertThat(summary.causes().get(1).checks().get(2).reason()).isEqualTo(QualityCauseClassifier.NOT_SEALED);
        assertThat(summary.causes().get(3).checks().get(3).details()).contains("level=IDENTITY_AWARE",
                "unknown=OnCall");
        assertThat(summary.causes().get(4).scope()).isEqualTo("tenant-b");
        // A tenant reads its own decisions only.
        assertThat(causes.ofDecisions("tenant-b", from, to).causes()).extracting(PromptQualityCauses.Cause::observationId)
                .containsExactly("obs-6");
        assertThat(causes.ofDecisions("tenant-c", from, to).causes()).isEmpty();
        assertThat(causes.find("tenant-c", summary.causes().get(4).id())).isEmpty();

        // A decision can be put down to an input error by hand.
        PromptQualityCauses.Cause byHand = causes.correct(SCOPE, summary.causes().get(1).id(),
                QualityCause.INPUT_ERROR, "admin-b");
        assertThat(byHand.category()).isEqualTo(QualityCause.INPUT_ERROR);
        assertThat(byHand.previousCategory()).isEqualTo(QualityCause.FORMAT_AND_MODEL);

        // The evidence audit inspects the seal of obs-1 later: one fact differs from the host's records.
        inspected("package-1", 3, 1);
        List<Map<String, Object>> before = rows();
        PromptQualityCauses.Summary after = causes.ofDecisions(SCOPE, from, to);
        assertThat(categories(after)).containsEntry("obs-1", QualityCause.INPUT_ERROR)
                .containsEntry("obs-2", QualityCause.INPUT_ERROR);
        PromptQualityCauses.Cause audited = after.causes().get(0);
        assertThat(audited.ruleCategory()).isEqualTo(QualityCause.INPUT_ERROR);
        assertThat(audited.checks().get(2).details()).containsExactly("matched=3", "mismatched=1", "unverifiable=0");
        assertThat(audited.fix()).isEqualTo(QualityCauseFix.COLLECTOR_OR_RECORDS);
        assertThat(after.causes().get(1).ruleCategory()).isEqualTo(QualityCause.FORMAT_AND_MODEL);
        assertThat(after.forNewVersion()).isEmpty();
        // Only the row whose rule came to another result was written again.
        List<Map<String, Object>> changed = rows().stream().filter(row -> !before.contains(row)).toList();
        assertThat(changed).extracting(row -> row.get("observation_id")).containsExactly("obs-1");
    }

    @Test
    void theRuleBasisIsKeptAsTheChecksInTheOrderOfPrecedence() throws Exception {
        long id = aDoneMeasurement();
        causes(LIMIT).classifyMeasurement(id);
        String basis = jdbc.queryForObject("select rule_basis from ctxa_prompt_version_case_cause where case_key = ?"
                + " and run_number = 1", String.class, "S04");
        JsonNode read = JSON.readTree(basis);
        assertThat(read.path("source").asText()).isEqualTo("MEASUREMENT");
        assertThat(read.path("basis").asText()).isEqualTo("BOTH");
        assertThat(read.path("actions").path("first").asText()).isEqualTo(QualityAction.ALLOW.name());
        assertThat(read.path("checks")).hasSize(7);
        assertThat(read.path("checks").get(6).path("state").asText()).isEqualTo("APPLIES");
        assertThat(read.path("checks").get(3).path("reason").asText())
                .isEqualTo(QualityCauseClassifier.NO_DECIDING_FACTS);
    }
}
