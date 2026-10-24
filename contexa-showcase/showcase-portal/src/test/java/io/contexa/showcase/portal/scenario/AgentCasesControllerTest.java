package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A7-3: the agent group reads an agent case as it is defined, apart from the scenario catalog, with the
 * legitimate case of the same delegated work beside it.
 */
class AgentCasesControllerTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    @Test
    void theAgentCasesStayApartFromTheScenarioCatalog() throws Exception {
        AgentTaskCatalog agentTasks = new AgentTaskCatalog(JSON);
        ScenarioCatalog scenarios = new ScenarioCatalog(JSON);

        assertThat(agentTasks.all()).extracting(ScenarioDefinition::key)
                .contains("N1", "N2", "N3", "T1", "T2", "T3", "T4", "T5");
        assertThat(agentTasks.all()).allSatisfy(task -> {
            assertThat(scenarios.find(task.key())).as(task.key() + " is in no protocol or benchmark").isEmpty();
            assertThat(agentTasks.sha256(task.key())).isPresent();
        });
    }

    @Test
    void theMainCaseShowsTheWorkItsDelegationAndItsNormalPair() throws Exception {
        AgentCasesController controller = new AgentCasesController(new AgentTaskCatalog(JSON),
                new StaticListableBeanFactory().getBeanProvider(RunStore.class), JSON);

        AgentCasesController.AgentCaseView view = controller.agentCase("T5").getBody();

        assertThat(view).isNotNull();
        assertThat(view.sender()).isEqualTo("DELEGATED_AGENT");
        assertThat(view.instruction()).containsKeys("ko", "en");
        assertThat(view.classification()).isEqualTo("THREAT");
        assertThat(view.delegation().project()).isEqualTo("HX-310");
        assertThat(view.delegation().operations()).contains("DOCUMENT_LIST");
        assertThat(view.delegation().validFromMinutes()).isEqualTo(-7 * 24 * 60L);
        assertThat(view.delegation().validUntilMinutes()).as("ended two hours before the work").isEqualTo(-120L);
        assertThat(view.normalPair()).isEqualTo("N1");
        assertThat(view.recorded()).as("no run store, no recording").isNull();
        AgentCasesController.AgentCaseView pair = controller.agentCase("N1").getBody();
        assertThat(pair.delegation().validUntilMinutes()).as("the pair works within the delegation").isPositive();
        assertThat(controller.agentCase("S13").getStatusCode().value()).isEqualTo(400);
        assertThat(controller.agentCase("T99").getStatusCode().value()).isEqualTo(404);
        assertThat(controller.agentRun("run-0123456789ab").getStatusCode().value()).isEqualTo(404);
    }
}
