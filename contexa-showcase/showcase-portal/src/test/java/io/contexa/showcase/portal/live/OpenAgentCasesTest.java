package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import io.contexa.showcase.portal.scenario.BurstChoice;
import io.contexa.showcase.portal.scenario.DelegationChoice;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent Agent중심-화면 AS-14: the agent cases the portal opens to visitors are a short list of the catalog's (five
 * by default, never more than eight), each short and with its own work; a visitor's start names a case, and a case that
 * is not open is not started, whatever the catalog holds.
 */
class OpenAgentCasesTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    private List<String> defaults() throws IOException {
        return LiveController.parseAgentTaskKeys(LiveController.DEFAULT_AGENT_TASKS, new AgentTaskCatalog(json));
    }

    @Test
    void byDefaultFiveCasesAreOpenAndTheMainCaseIsFirst() throws IOException {
        assertThat(defaults()).hasSize(5).first().isEqualTo("T5");
        assertThat(defaults()).doesNotHaveDuplicates();
    }

    @Test
    void everyOpenCaseIsAnAgentCaseWithItsOwnShortWork() throws IOException {
        AgentTaskCatalog catalog = new AgentTaskCatalog(json);
        for (String key : defaults()) {
            ScenarioDefinition task = catalog.find(key).orElseThrow();
            assertThat(task.agent()).as(key + " has an agent").isNotNull();
            assertThat(task.task()).as(key + " has work for the agent").isNotNull();
            assertThat(task.steps()).as(key + " asks for no history of days before the work").isEmpty();
            assertThat(task.task().maxToolCalls() == null || task.task().maxToolCalls() <= 12)
                    .as(key + " stays within the visitor's tool call cap").isTrue();
            assertThat(task.title()).as(key).containsKeys("ko", "en");
        }
    }

    @Test
    void theOpenCasesAreListedWithTheirSubjectAgent() throws IOException {
        List<LiveController.ScenarioOption> options = LiveController.openAgentCases(new AgentTaskCatalog(json), defaults());

        assertThat(options).hasSize(5);
        assertThat(options).allSatisfy(option -> assertThat(option.subject()).isEqualTo("AGENT"));
        assertThat(options).extracting(LiveController.ScenarioOption::key).containsExactlyElementsOf(defaults());
    }

    @Test
    void moreThanEightOpenCasesOrAnUnknownOneIsRefusedAtStart() throws IOException {
        AgentTaskCatalog catalog = new AgentTaskCatalog(json);
        String nine = "T5,N1,M14A,M22A,M10A,M13A,M16A,M19A,M19N";

        assertThat(LiveController.MOST_OPEN_AGENT_CASES).isEqualTo(8);
        assertThatThrownBy(() -> LiveController.parseAgentTaskKeys(nine, catalog)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("8");
        assertThatThrownBy(() -> LiveController.parseAgentTaskKeys("T5,NOPE", catalog))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("NOPE");
        assertThat(LiveController.parseAgentTaskKeys("T5, N1 ,", catalog)).containsExactly("T5", "N1");
    }

    // ---- AS-13: the burst case is started by name only with a number of requests, up to ten

    @Test
    void theBurstCaseIsStartedByNameAndNoOtherCaseIsOpenedByIt() throws IOException {
        AgentTaskCatalog agentTasks = new AgentTaskCatalog(json);
        ScenarioCatalog scenarios = new ScenarioCatalog(json);
        List<String> open = List.of("T5");

        assertThat(LiveController.startable(open, null, BurstChoice.BURST_CASE)).containsExactly("T5", "M41A");
        assertThat(LiveController.startable(open, "ED1", BurstChoice.BURST_CASE)).containsExactly("T5", "ED1", "M41A");
        assertThat(LiveController.startable(open, null, null)).containsExactly("T5");
        assertThat(LiveController.startable(List.of("T5", "M41A"), null, BurstChoice.BURST_CASE))
                .as("no duplicate").containsExactly("T5", "M41A");
        assertThat(LiveController.resolve("M41A", List.of(), scenarios, LiveController.startable(open, null, "M41A"),
                agentTasks)).isNotNull();
        assertThat(LiveController.resolve("M41A", List.of(), scenarios, open, agentTasks))
                .as("not started when the settings do not open it").isNull();
    }

    @Test
    void aBurstStartTakesANumberUpToTenAndRefusesTheRestWithoutChangingAnythingElse() throws IOException {
        AgentTaskCatalog agentTasks = new AgentTaskCatalog(json);
        ScenarioDefinition burst = agentTasks.find("M41A").orElseThrow();
        ScenarioDefinition other = agentTasks.find("T5").orElseThrow();
        ScenarioDefinition editable = agentTasks.find("ED1").orElseThrow();

        assertThat(LiveController.chosen(burst, null, 7).task().parallel().get(0).copies()).isEqualTo(7);
        assertThat(LiveController.chosen(other, null, null)).isSameAs(other);
        assertThat(LiveController.chosen(editable, new DelegationChoice(400, null, null), null).key()).isEqualTo("ED1");
        for (Integer bad : new Integer[]{11, 60, 0, -3}) {
            assertThatThrownBy(() -> LiveController.chosen(burst, null, bad)).as("copies " + bad)
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> LiveController.chosen(burst, null, null)).as("a live burst needs its number")
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> LiveController.chosen(other, null, 5)).as("a case that is no burst takes no number")
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> LiveController.chosen(burst, new DelegationChoice(400, null, null), 5))
                .as("only the editable case takes a delegation").isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aStartResolvesToAnOpenCaseOrAPersonScenarioAndToNothingElse() throws IOException {
        AgentTaskCatalog agentTasks = new AgentTaskCatalog(json);
        ScenarioCatalog scenarios = new ScenarioCatalog(json);
        String person = scenarios.all().iterator().next().key();
        List<String> open = List.of("T5", "N1");

        assertThat(LiveController.resolve("N1", List.of(person), scenarios, open, agentTasks)).isNotNull();
        assertThat(LiveController.resolve(person, List.of(person), scenarios, open, agentTasks)).isNotNull();
        assertThat(LiveController.resolve("M13A", List.of(person), scenarios, open, agentTasks))
                .as("a case of the catalog that is not open").isNull();
        assertThat(LiveController.resolve("M14A", List.of(person), scenarios, open, agentTasks)).isNull();
        assertThat(LiveController.resolve(person, List.of(), scenarios, open, agentTasks))
                .as("a person scenario the live settings do not list").isNull();
        assertThat(LiveController.resolve("../T5", List.of(person), scenarios, open, agentTasks)).isNull();
    }
}
