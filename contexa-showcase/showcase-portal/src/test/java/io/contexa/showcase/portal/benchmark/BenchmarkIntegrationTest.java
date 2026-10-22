package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.live.DecisionWaits;
import io.contexa.showcase.portal.measured.MeasuredCases;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.spec.ExecutionSpec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

/**
 * W5, V-13 and V-18 on a real database: the benchmark of a measurement setting counts only the completed, unforced
 * protocol runs of that setting, whichever protagonist's template they were cloned from and with or without a model
 * call (H-22). A forced decision, a failed run, a run of another setting and a visitor's run never enter the scores;
 * a forced visitor run never enters the visitors' figures. The expected numbers are worked out in the comments.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
class BenchmarkIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String SIGNING_KEY = randomKey();
    private static final Instant NOW = Instant.parse("2026-10-07T12:00:00Z");
    private static final String SETTING = "5".repeat(64);
    private static final String OTHER_SETTING = "6".repeat(64);
    private static final String PROMPT = "b".repeat(64);
    private static final String SPEC_ADMIN = "1".repeat(64);
    private static final String SPEC_ENGINEER = "2".repeat(64);
    private static final String SPEC_NO_CALL = "3".repeat(64);
    private static final String SPEC_OTHER = "4".repeat(64);
    private static final String THREAT = """
            {"oracle": {"classification": "THREAT", "allowedEngineActions": ["BLOCK", "CHALLENGE", "ESCALATE"]},
             "steps": [{}]}""";
    private static final String NORMAL = """
            {"oracle": {"classification": "NORMAL", "allowedEngineActions": ["ALLOW", "CHALLENGE"]}, "steps": [{}]}""";
    private static final String COMPOSED = """
            {"oracle": {"classification": "COMPOSED", "allowedEngineActions": []}, "steps": [{}]}""";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", () -> SIGNING_KEY);
    }

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    ScenarioCatalog scenarios;

    @Autowired
    ObjectMapper json;

    @Test
    void aSettingCountsOnlyItsOwnUnforcedProtocolRuns() {
        world();
        NamedParameterJdbcTemplate named = new NamedParameterJdbcTemplate(jdbc);
        BenchmarkService benchmark = new BenchmarkService(named, new RunScores(named, scenarios, json), scenarios,
                json, Map.of(), null, Clock.fixed(NOW, ZoneOffset.UTC));

        BenchmarkView view = benchmark.view(null).orElseThrow();

        assertThat(view.spec().settingHash()).as("the latest setting").isEqualTo(SETTING);
        assertThat(view.specs()).extracting(BenchmarkView.Spec::settingHash).containsExactly(SETTING, OTHER_SETTING);
        // t1, t2 (adm-a's template), n1 (eng-k's template) and r1 (refused before any analysis) share the setting.
        assertThat(view.spec().protocolRuns()).isEqualTo(4);
        assertThat(view.spec().templates()).containsExactly("tpl-adm-a-1", "tpl-eng-k-1");
        assertThat(view.spec().templateVersions()).as("learned under one version").containsExactly("v1");
        assertThat(view.spec().promptHashes()).containsExactlyInAnyOrder(PROMPT, ExecutionSpec.NO_MODEL_CALL);
        assertThat(view.scope().runs()).isEqualTo(4);
        assertThat(view.scope().attackRuns()).isEqualTo(3);
        assertThat(view.scope().normalRuns()).isEqualTo(1);
        assertThat(view.scope().protocols()).extracting(BenchmarkView.Protocol::protocolId).containsExactly("p-1");
        // p-1 planned three cases once; t1, t2, r1, n1 and u1 completed, x1 failed and f1 carried a forced decision.
        assertThat(view.scope().protocols().get(0)).satisfies(protocol -> {
            assertThat(protocol.cases()).isEqualTo(3);
            assertThat(protocol.plannedRuns()).isEqualTo(3);
            assertThat(protocol.completedRuns()).isEqualTo(5);
            assertThat(protocol.failedRuns()).isEqualTo(1);
            assertThat(protocol.forcedRuns()).isEqualTo(1);
        });
        // BM-S9: how many times each case was sent, as measured (A3 twice: t1, t2; R1 and A3T once).
        assertThat(view.scope().fewestRunsPerCase()).isEqualTo(1);
        assertThat(view.scope().mostRunsPerCase()).isEqualTo(2);
        assertThat(view.protocolRunsWithoutSetting()).as("u1 recorded no setting").isEqualTo(1);
        // Control D: t1 missed (10 items out), t2 and r1 stopped; n1 passed.
        BenchmarkView.ControlScore d = view.controls().stream().filter(score -> score.control().equals("D"))
                .findFirst().orElseThrow();
        assertThat(d.stopped().hits()).isEqualTo(2);
        assertThat(d.stopped().total()).isEqualTo(3);
        assertThat(d.exposedItems()).isEqualTo(10);
        assertThat(d.falseBlock().hits()).isZero();
        assertThat(d.falseBlock().total()).isEqualTo(1);
        // Decisions of t1 (1000 ms), n1 (2000 ms) and t2 (3000 ms); the forced run's 50 ms and the other setting's
        // 9000 ms are left out.
        assertThat(view.engine().decisions()).isEqualTo(3);
        assertThat(view.engine().analysisP50Ms()).isEqualTo(2000L);
        assertThat(view.engine().analysisP95Ms()).isEqualTo(3000L);
        assertThat(view.engine().analysisMeasured()).isEqualTo(3);
        // BM-S4: the three timed decisions (1, 2 and 3 s) fall in the first bin; the last bin is open-ended.
        assertThat(view.engine().analysisBins()).extracting(BenchmarkView.AnalysisBin::decisions)
                .containsExactly(3L, 0L, 0L, 0L, 0L, 0L, 0L);
        assertThat(view.engine().analysisBins()).extracting(BenchmarkView.AnalysisBin::fromMs)
                .containsExactly(0L, 5000L, 10000L, 15000L, 20000L, 30000L, 60000L);
        assertThat(view.engine().analysisBins().get(6).toMs()).isNull();
        // The engine recorded 9000, 11000 and 10000 tokens and 1, 2 and 1 model calls for those decisions.
        assertThat(view.engine().tokensPerDecision()).isEqualTo(10000.0);
        assertThat(view.engine().tokensMeasured()).isEqualTo(3);
        assertThat(view.engine().modelCallsPerDecision()).isCloseTo(4.0 / 3, within(1e-9));
        // PB-3 (G4): t1 applied its model's answer, t2 not (its last answer named another action), n1 had no model
        // answer recorded (held apart); the other setting's and the forced run's decisions are left out.
        assertThat(view.engine().agreement()).isEqualTo(new BenchmarkView.ModelAgreement(3, 2, 1, 0, 1));
        // BM-S6: the explanation each last answer judged most likely, by the run's truth (n1's decision has no model
        // answer); t2 was asked again once for a citation (its fact ID read as P#) and its answer moved.
        BenchmarkView.Reasoning reasoning = view.engine().reasoning();
        assertThat(reasoning.mostLikely()).isEqualTo(Map.of("THREAT", Map.of("H1", 1L, "H2", 1L)));
        // V-46: the same decisions by the action each applied, so "judged legitimate work in an attack run" can say
        // how many of those decisions still refused.
        assertThat(reasoning.mostLikelyActions()).isEqualTo(Map.of("THREAT",
                Map.of("H1", Map.of("ALLOW", 1L), "H2", Map.of("BLOCK", 1L))));
        assertThat(reasoning.retried()).isEqualTo(1);
        assertThat(reasoning.retryKinds()).isEqualTo(Map.of("REASON_CODE_MISMATCH", 1L));
        assertThat(reasoning.topRetryReasons()).containsExactly(new BenchmarkView.RetryReason(
                "PAST_RECORD_SAME_TARGET P# (the code does not cite PAST_RECORDS.PastRecordCounts)", 1));
        assertThat(reasoning.flips()).isEqualTo(Map.of("BLOCK->ESCALATE", 1L));
        // A3 opens t1 then t2; their risk scores 0.2 and 0.9 make its spread. R1 had no decision.
        assertThat(view.cases()).filteredOn(row -> row.key().equals("A3")).singleElement().satisfies(row -> {
            assertThat(row.runIds()).containsExactly("t1", "t2");
            assertThat(row.risk()).isEqualTo(new BenchmarkView.RiskSpread(0.2, 0.9, 2, 2));
            // Contexa stopped t2 and missed t1; the rule controls let both through.
            assertThat(row.cells().get("D")).isEqualTo(new BenchmarkView.Cell(1, 2));
            assertThat(row.cells().get("A")).isEqualTo(new BenchmarkView.Cell(0, 2));
        });
        assertThat(view.cases()).filteredOn(row -> row.key().equals("R1")).singleElement()
                .satisfies(row -> assertThat(row.risk()).isEqualTo(new BenchmarkView.RiskSpread(null, null, 0, 0)));
        assertThat(view.wrongRuns()).extracting(BenchmarkView.WrongRun::runId).containsExactly("t1");
        assertThat(view.wrongRunCount()).isEqualTo(1);
        assertThat(view.unresolvedRuns()).isZero();
        assertThat(view.suites()).as("none of A3 and R1 belongs to a named case group").isEmpty();
        assertThat(view.riskJudged()).as("t2's BLOCK was the only decision not to allow, and t2 was stopped")
                .isEqualTo(new BenchmarkView.RiskJudged(1, 1, Map.of("STATIC_REFUSAL", 0L, "BEFORE_RESPONSE", 0L,
                        "NEXT_REQUEST", 0L, "JUDGED_ALLOW", 0L, "OTHER", 1L), List.of()));
        // V-01: the run of the kind "other" with its case, result and the shape of its one step.
        assertThat(view.judgmentOthers()).containsExactly(new BenchmarkView.JudgmentRun("t2", "A3", "STOPPED", 0,
                List.of(new BenchmarkView.JudgmentStep(1, "BLOCK", "NEXT_REQUEST", "MODEL", false))));
        // t1 missed with every decision to allow; r1 was refused by the role check; t2 was refused at its only step
        // although its recorded decision applied from the next request, a shape none of the kinds describes.
        assertThat(view.judgmentTiming()).containsExactly(Map.entry("STATIC_REFUSAL", 1L),
                Map.entry("BEFORE_RESPONSE", 0L), Map.entry("NEXT_REQUEST", 0L), Map.entry("JUDGED_ALLOW", 1L),
                Map.entry("OTHER", 1L));
        // BM-S3: t1 let its 10 items out before a decision to allow; r1 and t2 let nothing out.
        assertThat(view.judgmentExposure()).containsExactly(Map.entry("STATIC_REFUSAL", 0L),
                Map.entry("BEFORE_RESPONSE", 0L), Map.entry("NEXT_REQUEST", 0L), Map.entry("JUDGED_ALLOW", 10L),
                Map.entry("OTHER", 0L));
        assertThat(view.cases()).filteredOn(row -> row.key().equals("R1")).singleElement()
                .satisfies(row -> assertThat(row.decisionSources()).isEqualTo(Map.of("STATIC_AUTHORIZATION", 1L)));
        // Visitors: v1 counts with its call and its assessment, c1 (a composed lab run without a ground truth) with
        // its "unsure" call among all calls only; the forced visitor run v2 and its own are left out.
        assertThat(view.observations().liveRuns()).isEqualTo(2);
        assertThat(view.observations().labRuns()).isEqualTo(1);
        assertThat(view.observations().composedRuns()).isEqualTo(1);
        assertThat(view.observations().predictionsAll()).isEqualTo(2);
        assertThat(view.observations().predictions().hits()).isEqualTo(1);
        assertThat(view.observations().predictions().total()).isEqualTo(1);
        assertThat(view.observations().unsurePredictions()).isZero();
        assertThat(view.observations().assessments()).isEqualTo(1);

        // The decision wait (common-2): A3's step 1 took 1000 and 3000 ms in the latest setting (the forced f1, the
        // visitors' v1 and the other setting's o1 are left out), and the middle is taken as the benchmark takes it.
        DecisionWaits waits = new DecisionWaits(named, () -> Optional.of(SETTING), Clock.fixed(NOW, ZoneOffset.UTC));
        assertThat(waits.estimate("A3", 1, NOW.minusMillis(400)))
                .hasValue(new DecisionWaits.Wait(3000, 2, SETTING, 400, 3));
        assertThat(waits.estimate("A3", 1, NOW.minusMillis(3500))).as("waited past the middle")
                .hasValue(new DecisionWaits.Wait(3000, 2, SETTING, 3500, null));
        assertThat(waits.estimate("A3", 2, NOW)).as("no measured decision of the step").isEmpty();
        assertThat(new DecisionWaits(named, Optional::empty, Clock.fixed(NOW, ZoneOffset.UTC)).estimate("A3", 1, NOW))
                .as("no measurement").isEmpty();

        // The "measured N times" lines (E1-5): A3's runs in the latest setting's latest measurement, t1 missed with 10
        // items out after 1000 ms and t2 stopped after 3000 ms; the forced, failed and unset runs are left out.
        // How long Contexa's application took to answer step 1: t1 answered at once, t2 held the response.
        jdbc.update("update run_arm_result set elapsed_ms = 70 where run_id = 't1' and control = 'D'");
        jdbc.update("update run_arm_result set elapsed_ms = 3100 where run_id = 't2' and control = 'D'");
        MeasuredCases measured = new MeasuredCases(named, new RunScores(named, scenarios, json),
                () -> Optional.of(SETTING), Clock.fixed(NOW, ZoneOffset.UTC));
        MeasuredCases.View a3 = measured.view("A3").orElseThrow();
        assertThat(a3.protocolId()).isEqualTo("p-1");
        assertThat(a3.runs()).isEqualTo(2);
        assertThat(a3.list()).extracting(MeasuredCases.MeasuredRun::runId).containsExactly("t1", "t2");
        assertThat(a3.results()).containsExactly(Map.entry("MISSED", 1L), Map.entry("STOPPED", 1L));
        assertThat(a3.allSame()).isFalse();
        assertThat(a3.analysisMs()).isEqualTo(new MeasuredCases.Range(1000, 3000));
        assertThat(a3.exposedItems()).isEqualTo(new MeasuredCases.Range(0, 10));
        assertThat(a3.list().get(1).engineAction()).isEqualTo("BLOCK");
        assertThat(a3.responseMs()).isEqualTo(new MeasuredCases.Range(70, 3100));
        assertThat(a3.list()).extracting(MeasuredCases.MeasuredRun::responseMs).containsExactly(70L, 3100L);
        assertThat(a3.middleRun()).as("the lower middle of two decided runs by analysis time").isEqualTo("t1");
        assertThat(measured.view("S10")).as("a case without a measured run").isEmpty();

        BenchmarkView other = benchmark.view(OTHER_SETTING).orElseThrow();
        assertThat(other.scope().runs()).isEqualTo(1);
        assertThat(other.engine().analysisP50Ms()).isEqualTo(9000L);
        assertThat(other.engine().analysisBins()).extracting(BenchmarkView.AnalysisBin::decisions)
                .containsExactly(0L, 1L, 0L, 0L, 0L, 0L, 0L);
        assertThat(benchmark.view("7".repeat(64))).as("a setting without protocol runs").isEmpty();
    }

    private void world() {
        template("tpl-adm-a-0", "adm-a", "v0");
        template("tpl-adm-a-1", "adm-a", "v1");
        template("tpl-eng-k-1", "eng-k", "v1");
        spec(SPEC_ADMIN, PROMPT, "tpl-adm-a-1");
        spec(SPEC_ENGINEER, PROMPT, "tpl-eng-k-1");
        spec(SPEC_NO_CALL, ExecutionSpec.NO_MODEL_CALL, "tpl-adm-a-1");
        spec(SPEC_OTHER, PROMPT, "tpl-adm-a-0");
        protocol("p-0", NOW.minusSeconds(7200));
        protocol("p-1", NOW.minusSeconds(3600));
        // The other setting's protocol, earlier: o1 stops an attack after 9000 ms of analysis.
        run("o1", "A3", THREAT, "COMPLETED", null, "p-0", OTHER_SETTING, SPEC_OTHER, false, NOW.minusSeconds(7000));
        arms("o1", "REFUSED", null);
        decision("o1", "BLOCK", 9000L, 0.95, 9000L, 1);
        // t1 (A3, threat): D lets 10 items out and allows it (1000 ms).
        run("t1", "A3", THREAT, "COMPLETED", null, "p-1", SETTING, SPEC_ADMIN, false, NOW.minusSeconds(3500));
        arms("t1", "DELIVERED", null);
        UUID t1 = decision("t1", "ALLOW", 1000L, 0.2, 9000L, 1);
        // PB-3: t1's one model call answered the action it applied.
        exchange(t1, "t1", 1, "{\"action\":\"ALLOW\",\"reason\":\"usual work\",\"hypotheses\":"
                + "[{\"id\":\"H1\",\"assessment\":\"MOST_LIKELY\"},{\"id\":\"H2\",\"assessment\":\"UNLIKELY\"}]}");
        // t2 (A3, threat): D blocks it (3000 ms).
        run("t2", "A3", THREAT, "COMPLETED", null, "p-1", SETTING, SPEC_ADMIN, false, NOW.minusSeconds(3400));
        arms("t2", "REFUSED", null);
        UUID t2 = decision("t2", "BLOCK", 3000L, 0.9, 11000L, 2);
        // PB-3: t2's last model call answered another action than the one applied.
        exchange(t2, "t2", 1, "{\"action\":\"BLOCK\"}");
        // BM-S6: the second call was a corrective retry for a citation, and the answer moved from BLOCK to ESCALATE.
        exchange(t2, "t2", 2, "{\"action\": \"ESCALATE\",\"hypotheses\":[{\"id\":\"H2\",\"assessment\":\"MOST_LIKELY\"}]}",
                "=== REQUEST ===\nThe previous answer did not follow the output contract or cited what the lines do not"
                        + " state (REASON_CODE_MISMATCH: PAST_RECORD_SAME_TARGET P1 (the code does not cite"
                        + " PAST_RECORDS.PastRecordCounts)). Answer again with one JSON object. Your action is yours.");
        // r1 (R1, threat): the role check refuses it before any analysis, so no model call and no decision.
        run("r1", "R1", THREAT, "COMPLETED", null, "p-1", SETTING, SPEC_NO_CALL, false, NOW.minusSeconds(3300));
        arms("r1", "REFUSED", null);
        // n1 (A3T, normal work, eng-k's template): D allows it (2000 ms).
        run("n1", "A3T", NORMAL, "COMPLETED", null, "p-1", SETTING, SPEC_ENGINEER, false, NOW.minusSeconds(3200));
        arms("n1", "DELIVERED", null);
        decision("n1", "ALLOW", 2000L, null, 10000L, 1);
        // Left out of the scores: a forced decision and a failed run of the same protocol and setting.
        run("f1", "A3", THREAT, "COMPLETED", "CHALLENGE", "p-1", SETTING, SPEC_ADMIN, false, NOW.minusSeconds(3100));
        arms("f1", "REFUSED", null);
        decision("f1", "CHALLENGE", 50L, 0.5, 100L, 1);
        run("x1", "A3", THREAT, "FAILED", null, "p-1", SETTING, SPEC_ADMIN, false, NOW.minusSeconds(3000));
        // A protocol run that recorded no setting belongs to no setting's scores and is counted apart.
        run("u1", "A3", THREAT, "COMPLETED", null, "p-1", null, SPEC_ADMIN, false, NOW.minusSeconds(2900));
        // Visitors' live runs under the same setting: v1 counts apart from the scores, the forced v2 not at all.
        run("v1", "A3", THREAT, "COMPLETED", null, null, SETTING, SPEC_ADMIN, true, NOW.minusSeconds(9000));
        arms("v1", "DELIVERED", null);
        decision("v1", "ALLOW", 500L, 0.1, 9000L, 1);
        run("v2", "A3", THREAT, "COMPLETED", "BLOCK", null, SETTING, SPEC_ADMIN, true, NOW.minusSeconds(8000));
        arms("v2", "REFUSED", "ACCOUNT_BLOCKED");
        run("c1", "A3", COMPOSED, "COMPLETED", null, null, SETTING, SPEC_ADMIN, true, NOW.minusSeconds(8500));
        jdbc.update("""
                insert into lab_composition (run_id, case_key, designed, changed, conditions, composed_at)
                values ('c1', 'A3', false, '["ticket"]'::jsonb, '{}'::jsonb, ?)""", Timestamp.from(NOW.minusSeconds(8600)));
        jdbc.update("""
                insert into visitor_prediction (run_id, visitor_hash, call, predicted_at)
                values ('c1', ?, 'UNSURE', ?)""", "f".repeat(64), Timestamp.from(NOW.minusSeconds(8600)));
        for (String visitorRun : new String[]{"v1", "v2"}) {
            jdbc.update("""
                    insert into visitor_prediction (run_id, visitor_hash, call, predicted_at)
                    values (?, ?, 'ATTACK', ?)""", visitorRun, "f".repeat(64), Timestamp.from(NOW.minusSeconds(9000)));
            jdbc.update("""
                    insert into visitor_assessment (run_id, step_no, visitor_hash, verdict, reasons, assessed_at)
                    values (?, 1, ?, 'UNSOUND', '["MISSED_SIGNAL"]'::jsonb, ?)""",
                    visitorRun, "f".repeat(64), Timestamp.from(NOW.minusSeconds(7200)));
        }
    }

    private void template(String templateId, String employee, String version) {
        jdbc.update("""
                insert into engine_template (template_id, employee_key, company_seed, company_anchor, company_sha256,
                    status, attempt, learned_under)
                values (?, ?, 20261005, date '2026-09-30', ?, 'READY', 1, ?)""",
                templateId, employee, "d".repeat(64), version);
    }

    private void spec(String specHash, String promptHash, String templateId) {
        jdbc.update("""
                insert into execution_spec (spec_id, spec_hash, code_commit, engine_version, effective_mode,
                    endpoint_protection, chat_model, embedding_model, embedding_dimensions, prompt_hash, template_id,
                    rule_version, time_zone)
                values (?, ?, 'abc123', '0.1.0', 'ENFORCE', '{}'::jsonb, 'gpt-5-nano', 'text-embedding-3-small', 1024,
                    ?, ?, ?, 'UTC')""", UUID.randomUUID(), specHash, promptHash, templateId, "c".repeat(64));
    }

    private void protocol(String protocolId, Instant startedAt) {
        jdbc.update("""
                insert into measurement_protocol (protocol_id, repeat, cases, started_at, finished_at)
                values (?, 1, '["A3", "A3T", "R1"]'::jsonb, ?, ?)""",
                protocolId, Timestamp.from(startedAt), Timestamp.from(startedAt.plusSeconds(900)));
    }

    private void run(String runId, String key, String definition, String status, String forced, String protocol,
                     String setting, String spec, boolean live, Instant startedAt) {
        String template = jdbc.queryForObject("select template_id from execution_spec where spec_hash = ?",
                String.class, spec);
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, template_id,
                    organization_id, tenant_id, client_ip, device, company_time, status, spec_hash, started_at,
                    finished_at, forced_action, live_visitor_hash, live_run, scenario_definition, protocol_id,
                    setting_hash)
                values (?, ?, 1, 'adm-a', ?, ?, 'org', 'tenant', '10.40.12.77', 'test', ?, ?, ?, ?, ?, ?, ?, ?,
                    cast(? as jsonb), ?, ?)""",
                runId, key, "v" + runId, template, Timestamp.from(startedAt), status, spec, Timestamp.from(startedAt),
                Timestamp.from(startedAt.plusSeconds(30)), forced, live ? "f".repeat(64) : null, live, definition,
                protocol, setting);
    }

    /** The rule controls in front let step 1 through with 10 items; control D answers as given. */
    private void arms(String runId, String d, String dRule) {
        for (String control : new String[]{"A", "B", "C1", "C2", "D"}) {
            String outcome = "D".equals(control) ? d : "DELIVERED";
            jdbc.update("""
                    insert into run_arm_result (run_id, step_no, control, request_id, operation, method, path,
                        company_time, http_status, outcome, delivered_items, sent_at, rule_id)
                    values (?, 1, ?, ?, 'EXPORT', 'POST', '/api/x', ?, ?, ?, ?, ?, ?)""",
                    runId, control, UUID.randomUUID(), Timestamp.from(NOW), "DELIVERED".equals(outcome) ? 200 : 403,
                    outcome, "DELIVERED".equals(outcome) ? 10 : 0, Timestamp.from(NOW),
                    "D".equals(control) ? dRule : null);
        }
    }

    private UUID decision(String runId, String action, long totalMs, Double risk, long tokens, int calls) {
        UUID requestId = UUID.randomUUID();
        jdbc.update("""
                insert into run_decision (request_id, run_id, step_no, final_action, proposed_action, unresolved,
                    applied, total_analysis_ms, risk_score, total_tokens, model_calls, records, events)
                values (?, ?, 1, ?, ?, false, 'NEXT_REQUEST', ?, ?, ?, ?, '[]'::jsonb, '[]'::jsonb)""",
                requestId, runId, action, action, totalMs, risk, tokens, calls);
        return requestId;
    }

    private void exchange(UUID requestId, String runId, int callNo, String answer) {
        exchange(requestId, runId, callNo, answer, null);
    }

    private void exchange(UUID requestId, String runId, int callNo, String answer, String userPrompt) {
        jdbc.update("""
                insert into run_model_exchange (request_id, call_no, run_id, step_no, answer, user_prompt, success)
                values (?, ?, ?, 1, ?, ?, true)""", requestId, callNo, runId, answer, userPrompt);
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
