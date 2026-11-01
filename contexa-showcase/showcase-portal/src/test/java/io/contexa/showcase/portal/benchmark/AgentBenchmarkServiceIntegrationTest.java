package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.agent.AgentTaskProof;
import io.contexa.showcase.portal.agent.AgentWork;
import io.contexa.showcase.portal.orchestrator.RunStore;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent Agent중심-화면 AS-11: the benchmark counts the agent runs of the operator's measurements by the one scoring
 * rule of the agent task (its proof), for the definitions in force only: what the existing controls let through together
 * and how much of that Contexa stopped, the false blocks of the normal cases, how the same case and path varied, and the
 * cases nothing was measured for. Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
class AgentBenchmarkServiceIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final Instant AT = Instant.parse("2026-10-25T05:00:00Z");
    /** The measurement setting the benchmark shows by default, and the specifications of its build and an older one. */
    private static final String SETTING = "5".repeat(64);
    private static final String SPEC_NOW = "a".repeat(64);
    private static final String SPEC_OLD = "b".repeat(64);
    private static final String SETTINGS = "{\"layer1Model\": {\"model\": \"gpt-6-luna\"}}";

    private static RunStore store;
    private static JdbcTemplate jdbc;
    private static NamedParameterJdbcTemplate named;
    private static AgentBenchmarkService service;

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration/portal").cleanDisabled(true).load().migrate();
        DriverManagerDataSource dataSource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(), POSTGRES.getPassword());
        jdbc = new JdbcTemplate(dataSource);
        named = new NamedParameterJdbcTemplate(dataSource);
        store = new RunStore(named, new ObjectMapper().findAndRegisterModules());
        service = new AgentBenchmarkService(named, () -> Optional.of(SETTING));
        recordTheMeasurements();
    }

    private static void recordTheMeasurements() {
        // DEC-86: the current build is read from the setting's protocol run (a person case); the agent runs are matched
        // on its build fields, not on the setting hash, which also holds the template version.
        spec(SPEC_NOW, "46351d11c852", "2026.10.30-v21.19");
        spec(SPEC_OLD, "b78441c38bea", "2026.10.27-v21.17");
        jdbc.update("""
                insert into measurement_protocol (protocol_id, repeat, cases, started_at, finished_at)
                values ('p-now', 1, '["S13"]'::jsonb, ?, ?)""", Timestamp.from(AT), Timestamp.from(AT.plusSeconds(60)));
        store.start(new RunStore.RunStart("run-person", "S13", 1, "E-0042", "kim", null, "org", "tenant", "10.0.0.1",
                "laptop", AT, null, null, "{}", "9".repeat(64)));
        store.finish("run-person", "COMPLETED", null, Map.of());
        jdbc.update("update run set protocol_id = 'p-now', setting_hash = ?, spec_hash = ? where run_id = 'run-person'",
                SETTING, SPEC_NOW);
        String shaA = "1".repeat(64);
        String shaB = "2".repeat(64);
        // case X1 (attack), definition shaA: delegated path: 3 runs; two the existing controls all missed, Contexa stopped one
        run("run-b-1", "X1", shaA, "DELEGATED_AGENT", true, null, null, null, null, 1, false, AT.plusSeconds(1));
        run("run-b-2", "X1", shaA, "DELEGATED_AGENT", true, null, null, null, null, null, false, AT.plusSeconds(2));
        run("run-b-3", "X1", shaA, "DELEGATED_AGENT", true, null, null, 2, null, 2, false, AT.plusSeconds(3));
        // the same case on the autonomous path: one run, an existing control stopped it
        run("run-b-4", "X1", shaA, "AUTONOMOUS_AGENT", true, 1, null, null, null, 1, false, AT.plusSeconds(4));
        // a normal case X2 on the delegated path: Contexa stopped it once of two (a false block)
        run("run-b-5", "X2", shaA, "DELEGATED_AGENT", false, null, null, null, null, 1, false, AT.plusSeconds(5));
        run("run-b-6", "X2", shaA, "DELEGATED_AGENT", false, null, null, null, null, null, false, AT.plusSeconds(6));
        // a run of an older definition, a visitor's live run and a run of a case no longer in the catalog do not count
        run("run-b-7", "X1", shaB, "DELEGATED_AGENT", true, null, null, null, null, 1, false, AT.plusSeconds(7));
        run("run-b-8", "X1", shaA, "DELEGATED_AGENT", true, null, null, null, null, 1, true, AT.plusSeconds(8));
        run("run-b-9", "GONE", shaA, "DELEGATED_AGENT", true, null, null, null, null, 1, false, AT.plusSeconds(9));
        // a case whose truth is uncertain (the work is permitted, the claim false) is neither an attack nor a normal case
        run("run-b-11", "X4", shaA, "DELEGATED_AGENT", true, null, null, null, null, null, false, AT.plusSeconds(11));
        run("run-b-12", "X4", shaA, "DELEGATED_AGENT", true, null, null, null, null, 1, false, AT.plusSeconds(12));
        // a run of the model comparison (the business agent on Claude Sonnet 5.5, docs/agent 모델비교) is not the benchmark's agent
        run("run-b-10", "X1", shaA, "DELEGATED_AGENT", true, null, null, null, null, null, false, AT.plusSeconds(10),
                "claude-sonnet-5-5");
        // a run of the definition in force on an older build (another code commit and prompt bundle) is not counted
        run("run-b-13", "X1", shaA, "DELEGATED_AGENT", true, null, null, null, null, null, false, AT.plusSeconds(13));
        jdbc.update("update run set spec_hash = ? where run_id = 'run-b-13'", SPEC_OLD);
    }

    private static void spec(String specHash, String commit, String bundle) {
        jdbc.update("""
                insert into execution_spec (spec_id, spec_hash, code_commit, engine_version, effective_mode,
                    endpoint_protection, chat_model, embedding_model, embedding_dimensions, prompt_hash, rule_version,
                    time_zone, model_settings, prompt_bundle)
                values (?, ?, ?, '0.1.0', 'ENFORCE', '{}'::jsonb, 'gpt-5-nano', 'text-embedding-3-small', 1024, ?, ?,
                    'UTC', cast(? as jsonb), ?)""",
                UUID.randomUUID(), specHash, commit, "c".repeat(64), "d".repeat(64), SETTINGS, bundle);
    }

    private static void run(String runId, String key, String sha, String sender, boolean attack, Integer a, Integer b,
                     Integer c1, Integer c2, Integer d, boolean live, Instant at) {
        run(runId, key, sha, sender, attack, a, b, c1, c2, d, live, at, "gpt-6-luna");
    }

    /** A completed operator run of an agent case; {@code stops} are the first stop steps of A, B, C1, C2 and D (null: never). */
    private static void run(String runId, String key, String sha, String sender, boolean attack, Integer a, Integer b,
                     Integer c1, Integer c2, Integer d, boolean live, Instant at, String agentModel) {
        store.start(new RunStore.RunStart(runId, key, 1, "E-0042", "kim", null, "org", "tenant", "10.0.0.1", "laptop", at,
                null, live ? "v".repeat(64) : null, "{}", sha));
        store.finish(runId, "COMPLETED", null, Map.of());
        jdbc.update("update run set started_at = ?, spec_hash = ? where run_id = ?", Timestamp.from(at), SPEC_NOW, runId);
        AgentWork.Transcript work = new AgentWork.Transcript(agentModel, "prompt", "work", List.of(), "done", "ANSWERED",
                null, Map.of(), at, at.plusSeconds(5));
        Map<String, AgentTaskProof.Control> controls = Map.of(
                "A", control(a), "B", control(b), "C1", control(c1), "C2", control(c2), "D", control(d));
        store.agentTask(runId, sender, work, new AgentTaskProof.Proof(attack, null, "done", "ANSWERED", true, List.of(), null,
                1, 1, 1, controls, Map.of()));
    }

    private static AgentTaskProof.Control control(Integer stop) {
        return new AgentTaskProof.Control(0, 0, 0, 0, 0, stop, stop == null ? null : "REFUSED");
    }

    @Test
    void theRunsOfTheDefinitionsInForceAreCountedByPathWithWhatContexaAddedAndFalseBlocks() {
        String shaA = "1".repeat(64);

        AgentBenchmarkService.View view = service.view(List.of(new AgentBenchmarkService.CatalogCase("X1", shaA),
                new AgentBenchmarkService.CatalogCase("X2", shaA), new AgentBenchmarkService.CatalogCase("X3", shaA)));

        assertThat(view.scope().runs()).as("the Sonnet comparison run and the older build's run are not counted")
                .isEqualTo(6);
        assertThat(view.scope().cases()).isEqualTo(2);
        assertThat(view.build()).isEqualTo(new AgentBenchmarkService.Build(SETTING, "46351d11c852", "0.1.0", "ENFORCE",
                "2026.10.30-v21.19"));
        AgentBenchmarkService.PathRow delegated = view.byPath().stream()
                .filter(row -> "DELEGATED_AGENT".equals(row.path())).findFirst().orElseThrow();
        assertThat(delegated.runs()).isEqualTo(5);
        assertThat(delegated.attacks()).isEqualTo(3);
        assertThat(delegated.existingMissed()).as("run-b-1 and run-b-2: none of A, B, C1, C2 stopped").isEqualTo(2);
        assertThat(delegated.contexaStopped()).as("of those two, Contexa stopped run-b-1").isEqualTo(1);
        assertThat(delegated.normals()).isEqualTo(2);
        assertThat(delegated.falseBlocks()).isEqualTo(1);
        AgentBenchmarkService.PathRow autonomous = view.byPath().stream()
                .filter(row -> "AUTONOMOUS_AGENT".equals(row.path())).findFirst().orElseThrow();
        assertThat(autonomous.existingMissed()).isZero();
        assertThat(view.total().existingMissed()).isEqualTo(2);
        assertThat(view.total().contexaStopped()).isEqualTo(1);
        assertThat(view.total().contexaShare()).isEqualTo(0.5);
        assertThat(autonomous.contexaShare()).as("nothing missed, no share").isNull();
    }

    /**
     * docs/agent 모델비교 5절: a case whose truth is UNCERTAIN (M14A: 300 items inside the policy's exception, a false ticket
     * claimed) is no attack the existing controls "missed" and no normal case Contexa "blocked wrongly", so its runs are in
     * neither count; it is told apart as uncertain, not as a case nothing was measured for.
     */
    @Test
    void aCaseWhoseTruthIsUncertainIsInNeitherTheAttackNorTheNormalCountButIsTold() {
        String shaA = "1".repeat(64);

        AgentBenchmarkService.View view = service.view(List.of(new AgentBenchmarkService.CatalogCase("X1", shaA),
                new AgentBenchmarkService.CatalogCase("X2", shaA),
                new AgentBenchmarkService.CatalogCase("X4", shaA, "UNCERTAIN")));

        assertThat(view.scope().runs()).as("the two uncertain runs are not counted").isEqualTo(6);
        assertThat(view.total().attacks()).as("X1's four runs on both paths, none of X4's").isEqualTo(4);
        assertThat(view.total().normals()).isEqualTo(2);
        assertThat(view.contexaMissed()).as("X4's run no control stopped is no miss").containsExactly("X1");
        assertThat(view.notMeasured()).as("X4 was measured, only its truth is open").isEmpty();
        assertThat(view.uncertain()).containsExactly("X4");
    }

    @Test
    void withoutAMeasurementSettingThereIsNoBuildAndNoRunCounts() {
        AgentBenchmarkService none = new AgentBenchmarkService(named, Optional::empty);

        AgentBenchmarkService.View view = none.view(List.of(new AgentBenchmarkService.CatalogCase("X1", "1".repeat(64))));

        assertThat(view.build()).isNull();
        assertThat(view.scope().runs()).isZero();
        assertThat(view.notMeasured()).containsExactly("X1");
    }

    @Test
    void theCellsWhereTheSameInputEndedDifferentlyAndTheCasesNothingWasMeasuredForAreCounted() {
        AgentBenchmarkService.View view = service.view(List.of(new AgentBenchmarkService.CatalogCase("X1", "1".repeat(64)),
                new AgentBenchmarkService.CatalogCase("X2", "1".repeat(64)),
                new AgentBenchmarkService.CatalogCase("X3", "1".repeat(64))));

        // cells with two or more runs: X1 delegated (3 runs: Contexa stopped 2 of 3), X2 delegated (2 runs: stopped 1 of 2)
        assertThat(view.variation().cells()).isEqualTo(2);
        assertThat(view.variation().differing()).as("both cells ended differently across their runs").isEqualTo(2);
        assertThat(view.notMeasured()).containsExactly("X3");
        assertThat(view.contexaMissed()).as("X1 has an attack run (run-b-2) no control stopped").containsExactly("X1");
    }
}
