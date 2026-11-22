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
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.causes.PromptQualityCauses;
import io.contexa.contexaiam.admin.promptquality.measure.MeasuredQualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityRunLine;
import io.contexa.contexaiam.admin.promptquality.measure.QualityMeasureLock;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCauseScreen.CausesView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCauseScreen.Row;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCauseScreen.Tile;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Quality plan 3.5, 3.8 on a database with the schema of a new installation: the view of the wrong cases and their
 * causes reads the latest finished measurement of the scope or the one asked for: the seven causes in the order of
 * precedence with their counts, the conditions and what could not be computed; the wrong answers with the actions
 * given on the basis they are wrong on, the right answer, the case's name and the reasons it cited; with the decisions
 * rated inadequate in the last 90 days when asked; the count beside its tab; and the change of a cause an
 * administrator makes, refused as the causes refuse it.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityCauseScreenPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String SCOPE = PromptVersionService.PLATFORM_SCOPE;
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final List<String> SHIPPED = List.of("A1", "S04", "S10", "INS-S03", "S01");
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;
    private static List<QualityCase> shipped;

    private PromptQualityCases cases;
    private PromptQualityMeasurements measurements;
    private PromptQualityCauses causes;
    private PromptQualityCauseScreen screen;

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
    void theServicesOfTheView() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_case_cause, ctxa_prompt_version_measure_prompt,"
                + " ctxa_prompt_version_measure_answer, ctxa_prompt_version_measure, ctxa_prompt_version_case_set_member,"
                + " ctxa_prompt_version_case_set, ctxa_prompt_version_case_change, ctxa_prompt_version_case,"
                + " ctxa_prompt_version_part, ctxa_prompt_version, ctxa_zt_decision_outcome,"
                + " ctxa_ai_security_decision_observation CASCADE");
        QualityCaseSet set = new QualityCaseSet(QualityCaseSetReader.contexaDefault().name(), shipped);
        cases = new PromptQualityCases(() -> jdbc, JSON, false, PromptVersionAudit.none(), Clock.systemUTC(), null,
                () -> set);
        PromptVersionService versions = new PromptVersionService(() -> jdbc,
                SecurityDecisionPromptDocument.productReleases(), Map.of(), PromptVersionAudit.none(), Clock.systemUTC());
        measurements = new PromptQualityMeasurements(() -> jdbc, versions, cases,
                mock(PromptQualityMeasurements.Replayer.class), new PromptQualityRunLine(), QualityMeasureLock.local(),
                Map::of, null, null, JSON, null, "server-a");
        causes = new PromptQualityCauses(() -> jdbc, cases, JSON, () -> 90_000L, Clock.systemUTC());
        screen = new PromptQualityCauseScreen(() -> measurements, () -> causes, cases, () -> jdbc, JSON,
                Clock.systemUTC());
    }

    @AfterEach
    void closeTheRunner() {
        measurements.close();
    }

    @Test
    void theLatestFinishedMeasurementIsReadCauseByCauseWithItsWrongAnswers() {
        long done = aDoneMeasurement();
        measure(cases.publish(SCOPE, PROMPT, "admin"), PromptQualityMeasurements.RUNNING, 1);

        CausesView view = screen.causes(null, null, false).orElseThrow();

        assertThat(view.measureId()).as("the latest finished, not the one running").isEqualTo(done);
        assertThat(view.repeats()).isEqualTo(3);
        assertThat(view.answers()).isEqualTo(10);
        assertThat(view.withDecisions()).isFalse();
        assertThat(view.timeLimitMillis()).isEqualTo(90_000L);
        assertThat(view.tiles()).extracting(Tile::cause).containsExactly("FORMAT_AND_MODEL", "ENGINE_CHANGED",
                "INPUT_ERROR", "INPUT_SHORTAGE", "GROUNDING_ERROR", "UNSTABLE", "JUDGEMENT_ERROR");
        assertThat(view.tiles()).extracting(Tile::count).containsExactly(1, 1, 0, 3, 0, 2, 3);
        assertThat(view.tiles()).extracting(Tile::fix).containsExactly("MODEL_SETTING", "RULE_SETTING",
                "COLLECTOR_OR_RECORDS", "INTEGRATION", "PROMPT_OR_MODEL", "PROMPT_OR_MODEL", "PROMPT_VERSION");
        assertThat(view.tiles()).extracting(Tile::conditional).containsExactly(true, false, true, true, false, true,
                false);
        assertThat(view.tiles().get(3).notComputed()).isEqualTo(7);
        assertThat(view.rows()).hasSize(10).allSatisfy(row -> assertThat(row.source()).isEqualTo("MEASUREMENT"));

        Row engine = view.rows().stream().filter(row -> "S10".equals(row.caseKey())).findFirst().orElseThrow();
        assertThat(engine.cause()).isEqualTo("ENGINE_CHANGED");
        assertThat(engine.given()).as("wrong on its final action").containsExactly("ALLOW");
        assertThat(engine.allowed()).containsExactly("CHALLENGE", "ESCALATE", "BLOCK");
        assertThat(engine.name()).isEqualTo(MeasuredQualityGateSource.caseName(shipped.get(2)));
        assertThat(engine.reasons()).extracting(PromptQualityCauseScreen.Reason::code).containsExactly("NET", "TGT");
        assertThat(engine.reasons()).extracting(PromptQualityCauseScreen.Reason::fact).containsExactly("R3", null);
        Row judged = view.rows().stream().filter(row -> "S04".equals(row.caseKey())).findFirst().orElseThrow();
        assertThat(judged.cause()).isEqualTo("JUDGEMENT_ERROR");
        assertThat(judged.given()).containsExactly("ALLOW");
        assertThat(judged.reasons()).isEmpty();

        assertThat(screen.causes(SCOPE, done, false).orElseThrow().measureId()).isEqualTo(done);
        assertThat(screen.count(null, null)).isEqualTo(10L);
        assertThat(screen.count(SCOPE, done)).isEqualTo(10L);
    }

    @Test
    void theDecisionsRatedInadequateComeWithItWhenAsked() {
        aDoneMeasurement();
        Instant at = Instant.now().minus(2, ChronoUnit.HOURS);
        jdbc.update("insert into ctxa_ai_security_decision_observation (observation_id, request_id, final_action,"
                + " proposed_action, decision_source, llm_decision_present, context_coverage_level, http_method,"
                + " request_path, success, created_at) values ('obs-1', 'req-1', 'ALLOW', 'ALLOW', 'MODEL', true,"
                + " 'BUSINESS_AWARE', 'GET', '/api/documents/D-9', true, ?)", Timestamp.from(at));
        jdbc.update("insert into ctxa_zt_decision_outcome (outcome_id, observation_id, request_id, outcome_kind,"
                + " evaluation_reason, actor, occurred_at, created_at) values ('outcome-1', 'obs-1', 'req-1',"
                + " 'EVALUATED_INVALID', 'MISSED_SIGNAL', 'admin', ?, ?)", Timestamp.from(at), Timestamp.from(at));

        CausesView view = screen.causes(null, null, true).orElseThrow();

        assertThat(view.withDecisions()).isTrue();
        assertThat(view.decisions()).isEqualTo(1);
        assertThat(view.answers()).as("the measurement's own").isEqualTo(10);
        assertThat(view.rows()).hasSize(11);
        Row decision = view.rows().stream().filter(row -> "DECISION".equals(row.source())).findFirst().orElseThrow();
        assertThat(decision.name()).isEqualTo("GET /api/documents/D-9");
        assertThat(decision.observationId()).isEqualTo("obs-1");
        assertThat(decision.allowed()).isEmpty();
        assertThat(decision.given()).containsExactly("ALLOW");
        assertThat(view.tiles().stream().mapToInt(Tile::count).sum()).isEqualTo(11);
        assertThat(screen.count(null, null)).as("the tab counts the measurement's answers").isEqualTo(10L);
    }

    @Test
    void anAdministratorChangesACauseAsTheCausesAllow() {
        aDoneMeasurement();
        Row judged = screen.causes(null, null, false).orElseThrow().rows().stream()
                .filter(row -> "S04".equals(row.caseKey())).findFirst().orElseThrow();

        Row changed = screen.correct(null, judged.id(), "grounding_error", "admin-b");

        assertThat(changed.cause()).isEqualTo("GROUNDING_ERROR");
        assertThat(changed.ruleCause()).isEqualTo("JUDGEMENT_ERROR");
        assertThat(changed.corrected()).isTrue();
        assertThatThrownBy(() -> screen.correct(null, judged.id(), "INPUT_ERROR", "admin-b"))
                .isInstanceOfSatisfying(PromptQualityCauseScreen.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("DECISIONS_ONLY"));
        assertThatThrownBy(() -> screen.correct(null, judged.id(), "NOPE", "admin-b"))
                .isInstanceOfSatisfying(PromptQualityCauseScreen.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("CATEGORY"));
        assertThatThrownBy(() -> screen.correct(null, 999_999L, "UNSTABLE", "admin-b"))
                .isInstanceOfSatisfying(PromptQualityCauseScreen.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("NOT_FOUND"));
    }

    @Test
    void withoutAMeasurementOrTheCausesThereIsNoView() {
        assertThat(screen.causes(null, null, true)).isEmpty();
        assertThat(screen.count(null, null)).isNull();
        PromptQualityCauseScreen without = new PromptQualityCauseScreen(() -> measurements, () -> null, cases,
                () -> jdbc, JSON, null);
        aDoneMeasurement();
        assertThat(without.causes(null, null, true)).isEmpty();
        assertThat(without.count(null, null)).isNull();
        assertThatThrownBy(() -> without.correct(null, 1L, "UNSTABLE", "admin"))
                .isInstanceOfSatisfying(PromptQualityCauseScreen.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("UNAVAILABLE"));
    }

    // ----- fixtures, as the causes' own test lays them out -----

    private static long measure(PromptQualityCases.PublishedSet set, String status, int repeats) {
        Long id = jdbc.queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key,"
                + " version_number, version_content_hash, case_set_id, case_set_version, repeats, settings_hash,"
                + " settings, closing_rules, status, planned_answers, reusable_answers, expected_min_calls,"
                + " expected_max_calls, call_limit, created_by, created_at) values (?, ?, 1, 'version-hash', ?, ?, ?,"
                + " 'settings-hash', '{}', 'rules', ?, 0, 0, 0, 0, 0, 'admin', ?) returning id", Long.class, SCOPE,
                PROMPT, set.id(), set.version(), repeats, status, Timestamp.from(Instant.now()));
        return id != null ? id : -1;
    }

    private static void answer(long measure, String key, int run, String first, String model, String last, int cited,
                               int present, int flagged, long callMillis, boolean failed, String findings) {
        QualityCase item = shipped.stream().filter(one -> one.key().equals(key)).findFirst().orElseThrow();
        jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                + " case_content_hash, version_number, version_content_hash, settings_hash, run_number, outcome,"
                + " first_action, model_action, final_action, citation_state, cited_facts, present_facts, flagged_facts,"
                + " accurate_cited_facts, citation_findings, model_calls, decision_ms, measurement_failed,"
                + " failure_reason, created_at) values (?, ?, ?, ?, 1, 'version-hash', 'settings-hash', ?, ?, ?, ?, ?,"
                + " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", measure, SCOPE, key, item.contentHash(), run,
                failed ? "INFRASTRUCTURE_FAILURE" : "ANSWERED", failed ? null : first, failed ? null : model,
                failed ? null : last, failed ? null : "CHECKED", failed ? 0 : cited, failed ? null : present,
                failed ? null : flagged, failed ? 0 : present - flagged, findings,
                "[{\"pass\":1,\"callMs\":" + callMillis + ",\"gateWaitMs\":0,\"timeoutMs\":720000,\"failed\":false}]",
                callMillis + 100, failed, failed ? "INFRASTRUCTURE_FAILURE: busy" : null, Timestamp.from(Instant.now()));
    }

    /** The causes' own done measurement of three runs: ten wrong answers of five causes, one with its reasons. */
    private long aDoneMeasurement() {
        PromptQualityCases.PublishedSet set = cases.publish(SCOPE, PROMPT, "admin");
        long id = measure(set, PromptQualityMeasurements.DONE, 3);
        answer(id, "A1", 1, "ALLOW", "ALLOW", "ALLOW", 3, 3, 0, 6_000L, false, "[]");
        answer(id, "A1", 2, "BLOCK", "BLOCK", "BLOCK", 3, 3, 0, 6_000L, false, "[]");
        answer(id, "A1", 3, "ALLOW", "ALLOW", "ALLOW", 3, 3, 0, 6_000L, false, "[]");
        for (int run = 1; run <= 3; run++) {
            answer(id, "S04", run, "ALLOW", "ALLOW", "ALLOW", 3, 3, 0, 6_000L, false, "[]");
            answer(id, "INS-S03", run, "ALLOW", "ALLOW", "ALLOW", 3, 3, 1, 6_000L, false, "[]");
        }
        answer(id, "S10", 1, "ESCALATE", "ESCALATE", "ALLOW", 2, 2, 0, 6_000L, false,
                "[{\"code\":\"NET\",\"fact\":\"R3\",\"outcome\":\"MATCH\",\"present\":true},"
                        + "{\"code\":\"TGT\",\"fact\":\"\",\"outcome\":\"MATCH\",\"present\":true}]");
        answer(id, "S10", 2, "BLOCK", "BLOCK", "BLOCK", 2, 2, 0, 6_000L, false, "[]");
        answer(id, "S10", 3, "BLOCK", "BLOCK", "BLOCK", 2, 2, 0, 6_000L, false, "[]");
        answer(id, "S01", 1, "BLOCK", "BLOCK", "BLOCK", 2, 2, 0, 95_000L, false, "[]");
        answer(id, "S01", 2, "ALLOW", "ALLOW", "ALLOW", 2, 2, 0, 6_000L, false, "[]");
        answer(id, "S01", 3, null, null, null, 0, 0, 0, 0L, true, "[]");
        return id;
    }
}
