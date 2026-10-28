package io.contexa.showcase.portal.menu;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.agent.AgentWork;
import io.contexa.showcase.portal.agent.AgentTaskProof;
import io.contexa.showcase.portal.orchestrator.ModelPricing;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.orchestrator.RunStore;
import io.contexa.showcase.portal.scenario.AgentCasesController;
import io.contexa.showcase.portal.scenario.AgentPaths;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import io.contexa.showcase.portal.scenario.DelegationChoice;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.offset;

/**
 * docs/agent Agent중심-화면 AC-4a: the agent menu is a finite table of fifteen combinations (five cases on three
 * paths); a daily job runs each with the real engine and keeps the run that answers it, within a daily spending limit,
 * and a combination whose run fails keeps the answer it had. Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
class AgentMenuIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final Instant NOW = Instant.parse("2026-10-27T03:30:00Z");

    private static RunStore runs;
    private static JdbcTemplate jdbc;
    private static AgentMenuStore store;

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration/portal").cleanDisabled(true).load().migrate();
        DriverManagerDataSource dataSource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(), POSTGRES.getPassword());
        jdbc = new JdbcTemplate(dataSource);
        NamedParameterJdbcTemplate named = new NamedParameterJdbcTemplate(dataSource);
        runs = new RunStore(named, JSON);
        store = new AgentMenuStore(named);
    }

    /** A completed run row, as the job's runner would leave one. */
    private static String run(String runId, String caseKey, String sha) {
        runs.start(new RunStore.RunStart(runId, caseKey, 1, "E-0042", "kim", null, "org", "tenant", "10.0.0.1", "laptop",
                NOW, null, null, "{}", sha));
        runs.finish(runId, "COMPLETED", null, Map.of());
        return runId;
    }

    @Test
    void theMenuIsFiveCasesOnThreePathsAndTheEditableCasesEighteenChoicesOnThemAndEveryOneRuns() throws Exception {
        List<AgentMenu.Combo> combos = AgentMenu.combos();

        // docs/agent AC-4b: 15 combinations, then the editable case's 3 x 3 x 2 delegation choices on 3 paths = 54
        assertThat(combos).hasSize(69).doesNotHaveDuplicates();
        assertThat(combos.subList(0, 15)).allSatisfy(combo -> assertThat(combo.choice()).isNull());
        assertThat(combos.subList(15, 69)).allSatisfy(combo -> {
            assertThat(combo.caseKey()).isEqualTo("ED1");
            assertThat(combo.choice()).isNotNull();
            assertThat(combo.choice().isEmpty()).isFalse();
        });
        assertThat(combos.subList(15, 69)).extracting(combo -> combo.choice().key()).containsAll(
                DelegationChoice.every().stream().map(DelegationChoice::key).toList());
        AgentTaskCatalog catalog = new AgentTaskCatalog(JSON);
        AgentMenuJob job = new AgentMenuJob(catalog, JSON, scenario -> null, store, runIds -> 0d, 2.00,
                Clock.fixed(NOW, ZoneOffset.UTC));
        for (AgentMenu.Combo combo : combos) {
            ScenarioDefinition scenario = job.scenarioOf(combo);
            assertThat(scenario.task().sender()).as(combo.caseKey() + " on " + combo.path())
                    .isEqualTo(AgentPaths.sender(combo.path()));
        }
        assertThat(AgentMenu.has("ED1", "SESSION", new DelegationChoice(400, "EXPIRED", "READ_ONLY"))).isTrue();
        assertThat(AgentMenu.has("ED1", "SESSION", null)).as("the editable case is on the menu with a full choice").isFalse();
        assertThat(AgentMenu.has("ED1", "SESSION", new DelegationChoice(400, null, null))).as("a part of a choice").isFalse();
        assertThat(AgentMenu.has("M19A", "SESSION", new DelegationChoice(400, "VALID", "READ_EXPORT")))
                .as("another case takes no choice").isFalse();
    }

    /** AC-4b: a choice is part of the combination, so each of the editable case's choices keeps its own answer. */
    @Test
    void eachChoiceOfTheEditableCaseHasItsOwnAnswerAndTheChoiceChangesTheRunsDefinition() throws Exception {
        jdbc.update("delete from agent_menu");
        AgentMenuJob job = job();
        AgentMenu.Combo expired = new AgentMenu.Combo("ED1", "OAUTH2_DELEGATED", new DelegationChoice(400, "EXPIRED", "READ_EXPORT"));
        AgentMenu.Combo limit = new AgentMenu.Combo("ED1", "OAUTH2_DELEGATED", new DelegationChoice(400, "VALID", "READ_EXPORT"));
        agentRun("run-menu-e1", "ED1", job.shaOf(expired), NOW);
        agentRun("run-menu-e2", "ED1", job.shaOf(limit), NOW);

        store.keep("ED1", "OAUTH2_DELEGATED", expired.choice().key(), "run-menu-e1", job.shaOf(expired), NOW);
        store.keep("ED1", "OAUTH2_DELEGATED", limit.choice().key(), "run-menu-e2", job.shaOf(limit), NOW);

        assertThat(job.shaOf(expired)).as("another choice, another definition").isNotEqualTo(job.shaOf(limit));
        assertThat(job.scenarioOf(expired).facts().get(0).validUntilOffset()).isEqualTo(Duration.ofHours(-2));
        assertThat(job.scenarioOf(limit).facts().get(0).validUntilOffset()).isEqualTo(Duration.ofHours(3));
        assertThat(store.all()).hasSize(2);
        assertThat(store.find("ED1", "OAUTH2_DELEGATED", expired.choice().key()).orElseThrow().runId()).isEqualTo("run-menu-e1");
        assertThat(store.find("ED1", "OAUTH2_DELEGATED", limit.choice().key()).orElseThrow().runId()).isEqualTo("run-menu-e2");
        assertThat(store.find("ED1", "OAUTH2_DELEGATED")).as("no answer without a choice").isEmpty();
    }

    @Test
    void theVisitorReadsTheAnswerOfAChoiceWithTheDelegationItExecutedAndRefusesWhatIsNotOnTheMenu() throws Exception {
        jdbc.update("delete from agent_menu");
        AgentMenuJob job = job();
        DelegationChoice choice = new DelegationChoice(100, "REVOKED", "READ_ONLY");
        AgentMenu.Combo combo = new AgentMenu.Combo("ED1", "SESSION", choice);
        agentRun("run-menu-e3", "ED1", job.shaOf(combo), NOW);
        store.keep("ED1", "SESSION", choice.key(), "run-menu-e3", job.shaOf(combo), NOW);
        AgentMenuController controller = controller(NOW.plusSeconds(60), job);

        ResponseEntity<AgentMenuController.Answer> answer = controller.answer("ED1", "SESSION", 100, "REVOKED", "READ_ONLY");

        assertThat(answer.getStatusCode().value()).isEqualTo(200);
        AgentMenuController.Answer body = answer.getBody();
        assertThat(body.choice()).isEqualTo(choice);
        assertThat(body.caseView().delegation().maxItemsPerRequest()).as("the delegation of this choice").isEqualTo(100);
        assertThat(body.caseView().delegation().status()).isEqualTo("REVOKED");
        assertThat(body.caseView().delegation().operations()).doesNotContain("EXPORT");
        assertThat(body.stale()).isFalse();
        assertThat(controller.answer("ED1", "SESSION", 400, "VALID", "READ_EXPORT").getStatusCode().value())
                .as("a choice of the lists with no answer yet").isEqualTo(404);
        assertThat(controller.answer("ED1", "SESSION", 41, "VALID", "READ_EXPORT").getStatusCode().value())
                .as("a value outside the lists").isEqualTo(400);
        assertThat(controller.answer("ED1", "SESSION", 100, null, null).getStatusCode().value())
                .as("a part of a choice").isEqualTo(400);
        assertThat(controller.answer("ED1", "SESSION", null, null, null).getStatusCode().value())
                .as("the editable case without a choice").isEqualTo(400);
        assertThat(controller.answer("M19A", "SESSION", 100, "REVOKED", "READ_ONLY").getStatusCode().value())
                .as("another case takes no choice").isEqualTo(400);
        AgentMenuController.Listing listing = controller.menu();
        assertThat(listing.items()).singleElement().satisfies(item -> {
            assertThat(item.caseKey()).isEqualTo("ED1");
            assertThat(item.choice()).isEqualTo(choice);
        });
        assertThat(listing.delegationEdit()).containsKeys("case", "title", "quantities", "periods", "operations");
        assertThat(ENGINE_RUNS.get()).as("no model is called for a visit").isZero();
    }

    @Test
    void aKeptRunAnswersItsCombinationAndANewerOneReplacesIt() {
        jdbc.update("delete from agent_menu");
        run("run-menu-a1", "M19A", "a".repeat(64));
        run("run-menu-a2", "M19A", "b".repeat(64));

        store.keep("M19A", "SESSION", "run-menu-a1", "a".repeat(64), NOW);
        store.keep("M19A", "SESSION", "run-menu-a2", "b".repeat(64), NOW.plusSeconds(60));

        assertThat(store.find("M19A", "SESSION")).hasValueSatisfying(entry -> {
            assertThat(entry.runId()).isEqualTo("run-menu-a2");
            assertThat(entry.definitionSha256()).isEqualTo("b".repeat(64));
            assertThat(entry.ranAt()).isEqualTo(NOW.plusSeconds(60));
        });
        assertThat(store.find("M19A", "OAUTH2_AGENT")).isEmpty();
    }

    /** A run with an agent task record, the way the orchestrator leaves one. */
    private static void agentRun(String runId, String caseKey, String sha, Instant at) {
        run(runId, caseKey, sha);
        runs.agentTask(runId, "OAUTH2_AGENT", new AgentWork.Transcript("gpt-6-luna", "prompt", "work", List.of(), "done",
                "ANSWERED", null, Map.of(), at, at.plusSeconds(5)), new AgentTaskProof.Proof(true, null, "done",
                "ANSWERED", true, List.of(), null, 1, 1, 1, Map.of(), Map.of()));
    }

    private static AgentMenuController controller(Instant now, AgentMenuJob job) throws Exception {
        AgentTaskCatalog catalog = new AgentTaskCatalog(JSON);
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("runs", runs);
        return new AgentMenuController(store, job, catalog, new AgentCasesController(catalog,
                beans.getBeanProvider(RunStore.class), JSON), runs, Clock.fixed(now, ZoneOffset.UTC));
    }

    /** The runs the engine was asked for: a visitor's reading of the menu must leave this at zero. */
    private static final AtomicInteger ENGINE_RUNS = new AtomicInteger();

    private static AgentMenuJob job() throws Exception {
        return new AgentMenuJob(new AgentTaskCatalog(JSON), JSON, scenario -> {
            ENGINE_RUNS.incrementAndGet();
            return null;
        }, store, runIds -> 0d, 2.00, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void theVisitorSeesTheTableWithEachAnswersAgeAndAnOldOrOtherDefinitionMarkedStale() throws Exception {
        jdbc.update("delete from agent_menu");
        AgentMenuJob job = job();
        agentRun("run-menu-v1", "M19A", job.shaOf(new AgentMenu.Combo("M19A", "SESSION")), NOW);
        agentRun("run-menu-v2", "M19A", "e".repeat(64), NOW);
        agentRun("run-menu-v3", "M14A", job.shaOf(new AgentMenu.Combo("M14A", "OAUTH2_AGENT")), NOW);
        store.keep("M19A", "SESSION", "run-menu-v1", job.shaOf(new AgentMenu.Combo("M19A", "SESSION")), NOW);
        store.keep("M19A", "OAUTH2_AGENT", "run-menu-v2", "e".repeat(64), NOW);
        store.keep("M14A", "OAUTH2_AGENT", "run-menu-v3", job.shaOf(new AgentMenu.Combo("M14A", "OAUTH2_AGENT")),
                NOW.minus(Duration.ofHours(40)));

        AgentMenuController.Listing listing = controller(NOW.plusSeconds(3600), job).menu();

        assertThat(listing.paths()).containsExactly("OAUTH2_DELEGATED", "OAUTH2_AGENT", "SESSION");
        assertThat(listing.cases()).extracting(AgentMenuController.CaseOption::key)
                .containsExactly("M19A", "M19N", "M14A", "M16A", "M13A");
        assertThat(listing.cases()).allSatisfy(option -> assertThat(option.title()).containsKeys("ko", "en"));
        assertThat(listing.items()).hasSize(3);
        assertThat(listing.items()).filteredOn(item -> item.caseKey().equals("M19A") && item.path().equals("SESSION"))
                .singleElement().satisfies(item -> {
                    assertThat(item.stale()).as("this hour, this definition").isFalse();
                    assertThat(item.ranAt()).isEqualTo(NOW);
                });
        assertThat(listing.items()).filteredOn(item -> item.path().equals("OAUTH2_AGENT") && item.caseKey().equals("M19A"))
                .singleElement().satisfies(item -> assertThat(item.stale()).as("another definition").isTrue());
        assertThat(listing.items()).filteredOn(item -> item.caseKey().equals("M14A")).singleElement()
                .satisfies(item -> assertThat(item.stale()).as("forty hours old").isTrue());
    }

    @Test
    void oneAnswerIsTheCaseAsTheVisitorReadsItWithTheStoredRunAndNothingElseIsServed() throws Exception {
        jdbc.update("delete from agent_menu");
        AgentMenuJob job = job();
        String sha = job.shaOf(new AgentMenu.Combo("M19A", "SESSION"));
        agentRun("run-menu-w1", "M19A", sha, NOW);
        store.keep("M19A", "SESSION", "run-menu-w1", sha, NOW);
        AgentMenuController controller = controller(NOW.plusSeconds(60), job);

        ResponseEntity<AgentMenuController.Answer> answer = controller.answer("M19A", "SESSION");

        assertThat(answer.getStatusCode().value()).isEqualTo(200);
        AgentMenuController.Answer body = answer.getBody();
        assertThat(body.caseView().key()).isEqualTo("M19A");
        assertThat(body.caseView().recorded()).as("the menu keeps its own runs").isNull();
        assertThat(body.run()).containsEntry("stopReason", "ANSWERED").doesNotContainKey("systemPrompt");
        assertThat(body.ranAt()).isEqualTo(NOW);
        assertThat(body.stale()).isFalse();
        assertThat(controller.answer("M19A", "OAUTH2_AGENT").getStatusCode().value()).as("no answer yet").isEqualTo(404);
        assertThat(controller.answer("T5", "SESSION").getStatusCode().value()).as("not on the menu").isEqualTo(400);
        assertThat(controller.answer("M19A", "../x").getStatusCode().value()).isEqualTo(400);
        controller.menu();
        assertThat(ENGINE_RUNS.get()).as("reading the menu calls the engine and the model never").isZero();
    }

    private static void ledger(String runId, String kind, String model, long prompt, long cached, long completion) {
        jdbc.update("""
                insert into cost_ledger (entry_id, run_id, kind, model, prompt_tokens, cached_prompt_tokens,
                    completion_tokens, total_tokens, recorded_at) values (gen_random_uuid(), ?, ?, ?, ?, ?, ?, ?, ?)""",
                runId, kind, model, prompt, cached, completion, prompt + completion, Timestamp.from(NOW));
    }

    /**
     * AC-4 (6): what the job spent is the price of its own runs' ledger rows, each model by its own price and the
     * cached part of the prompt at the cached price; another run's rows are not counted, and neither are the visitors'.
     */
    @Test
    void whatTheJobSpentIsThePriceOfItsRunsLedgerRowsAndNothingElse() {
        run("run-menu-s1", "M19A", "a".repeat(64));
        run("run-menu-s2", "M14A", "a".repeat(64));
        run("run-menu-other", "M16A", "a".repeat(64));
        // luna: 0.10 in / 0.01 cached in / 0.50 out per million tokens
        ledger("run-menu-s1", "CHAT", "gpt-6-luna", 100_000, 40_000, 5_000);
        ledger("run-menu-s1", "AGENT_CHAT", "gpt-6-luna", 20_000, 0, 1_000);
        ledger("run-menu-s2", "CHAT", "gpt-6-luna", 10_000, 0, 0);
        ledger("run-menu-other", "CHAT", "gpt-6.1-sol", 1_000_000, 0, 1_000_000);
        NamedParameterJdbcTemplate named = new NamedParameterJdbcTemplate(jdbc.getDataSource());

        double spent = AgentMenuConfiguration.spent(named, ModelPricing.defaults(0.02), List.of("run-menu-s1", "run-menu-s2"));

        // (60,000 x 0.10 + 40,000 x 0.01 + 5,000 x 0.50) + (20,000 x 0.10 + 1,000 x 0.50) + (10,000 x 0.10), per million
        assertThat(spent).isEqualTo(0.0089 + 0.0025 + 0.001, offset(1e-9));
        assertThat(AgentMenuConfiguration.spent(named, ModelPricing.defaults(0.02), List.of())).isZero();
    }

    @Test
    void theJobRunsEveryCombinationKeepsWhatRanAndStopsAtItsDailyLimitWithoutLosingAnOldAnswer() throws Exception {
        jdbc.update("delete from agent_menu");
        // the third combination (M19A on OAUTH2_AGENT... the third of the table) already has an answer from before
        run("run-menu-old", "M19A", "c".repeat(64));
        AgentMenu.Combo failing = AgentMenu.combos().get(2);
        store.keep(failing.caseKey(), failing.path(), "run-menu-old", "c".repeat(64), NOW.minusSeconds(86_400));
        AtomicInteger sequence = new AtomicInteger();
        List<String> sent = new ArrayList<>();
        AgentMenuJob.Runner runner = scenario -> {
            int n = sequence.incrementAndGet();
            String runId = "run-menu-job-" + n;
            sent.add(scenario.key() + "/" + scenario.task().sender());
            run(runId, scenario.key(), "d".repeat(64));
            // the third run ends FAILED
            return new RunSummary(runId, scenario.key(), "u", "org", n == 3 ? "FAILED" : "COMPLETED", null, List.of());
        };
        // every run costs 0.40: with a limit of 2.00 the job stops after five runs
        AgentMenuJob.Spending spending = runIds -> runIds.size() * 0.40;
        AgentMenuJob job = new AgentMenuJob(new AgentTaskCatalog(JSON), JSON, runner, store, spending, 2.00,
                Clock.fixed(NOW, ZoneOffset.UTC));

        AgentMenuJob.Result result = job.refresh();

        assertThat(result.ran()).isEqualTo(4);
        assertThat(result.failed()).isEqualTo(1);
        assertThat(result.skipped()).isEqualTo(64);
        assertThat(result.stopped()).isEqualTo("DAILY_LIMIT");
        assertThat(result.spentUsd()).isEqualTo(2.0);
        assertThat(sent).as("the first five combinations, in the table's order").hasSize(5);
        assertThat(store.all()).hasSize(5).as("four new answers and the old one kept");
        assertThat(store.find(failing.caseKey(), failing.path()).orElseThrow().runId()).isEqualTo("run-menu-old");
        assertThat(store.jobs(1)).singleElement().satisfies(day -> {
            assertThat(day.ran()).isEqualTo(4);
            assertThat(day.failed()).isEqualTo(1);
            assertThat(day.skipped()).isEqualTo(64);
            assertThat(day.stopped()).isEqualTo("DAILY_LIMIT");
            assertThat(day.finishedAt()).isNotNull();
        });
    }
}
