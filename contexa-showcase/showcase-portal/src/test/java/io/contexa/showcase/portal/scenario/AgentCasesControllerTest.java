package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

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

    /** AS-14: every case the portal may open is read by its key, whatever kind of key the catalog uses. */
    @Test
    void anyCaseOfTheCatalogIsReadByItsKeyAndAnythingElseIsRefused() throws Exception {
        AgentCasesController controller = new AgentCasesController(new AgentTaskCatalog(JSON),
                new StaticListableBeanFactory().getBeanProvider(RunStore.class), JSON);

        for (String key : new String[]{"T5", "N1", "M14A", "M22A", "M10A", "VN1C", "M19N"}) {
            assertThat(controller.agentCase(key).getStatusCode().value()).as(key).isEqualTo(200);
        }
        assertThat(controller.agentCase("ZZ9").getStatusCode().value()).as("a key nobody defined").isEqualTo(404);
        for (String bad : new String[]{"../T5", "t5", "T5/x", "T5A1B2", "", "T 5"}) {
            assertThat(controller.agentCase(bad).getStatusCode().value()).as(bad).isEqualTo(400);
        }
    }

    /**
     * AS-13: the run of a burst carries the counts the portal makes of it (the same counts the stored measurements
     * carry), so the screen reads the visitor's own burst the way it reads the stored ones; a run of any other case
     * carries none.
     */
    @Test
    @SuppressWarnings("unchecked")
    void theRunOfABurstCarriesTheSameCountsAsAStoredMeasurementAndOtherRunsCarryNone() throws Exception {
        AgentTaskCatalog catalog = new AgentTaskCatalog(JSON);
        Map<String, Object> stored;
        try (InputStream stream = AgentCasesControllerTest.class.getResourceAsStream("/agent-runs/M41A-flights-on.json")) {
            stored = JSON.readValue(stream, new TypeReference<Map<String, Object>>() {
            });
        }
        Map<String, Object> run = new LinkedHashMap<>((Map<String, Object>) stored.get("run"));

        Map<String, Object> burst = AgentCasesController.withBurst(new LinkedHashMap<>(run),
                catalog.find("M41A"), JSON);
        Map<String, Object> other = AgentCasesController.withBurst(new LinkedHashMap<>(run),
                catalog.find("T5"), JSON);
        Map<String, Object> unknown = AgentCasesController.withBurst(new LinkedHashMap<>(run), Optional.empty(), JSON);

        assertThat(burst.get("burst")).isEqualTo(AgentSnapshotsController.summary(JSON.valueToTree(run)));
        assertThat((Map<String, Object>) burst.get("burst")).containsKeys("requests", "delivered", "refused", "busy",
                "withVerdict", "modelCalls", "firstStopStep", "deliveredAfterFirstStop");
        assertThat(other).doesNotContainKey("burst");
        assertThat(unknown).doesNotContainKey("burst");
        assertThat(run).as("the stored run itself is not touched").doesNotContainKey("burst");
    }

    /**
     * AS-12: the delegation a visitor sees on 6-3 is the one the run executed: the case's own, or the visitor's copy with its
     * one change (read back from the run's stored definition), with the quantity limit the delegation states.
     */
    @Test
    void theDelegationOfARunIsReadFromTheDefinitionItExecuted() throws Exception {
        AgentTaskCatalog catalog = new AgentTaskCatalog(JSON);
        ScenarioDefinition base = catalog.find("ED1").orElseThrow();
        ScenarioDefinition edited = new DelegationChoice(400, "REVOKED", "READ_ONLY").applyTo(base);

        AgentCasesController.Delegation own = AgentCasesController.delegationOf(base);
        AgentCasesController.Delegation changed = AgentCasesController.delegationOf(edited);

        assertThat(own.maxItemsPerRequest()).isEqualTo(40);
        assertThat(own.operations()).contains("EXPORT");
        assertThat(own.status()).isEqualTo("ACTIVE");
        assertThat(changed.maxItemsPerRequest()).isEqualTo(400);
        assertThat(changed.operations()).doesNotContain("EXPORT");
        assertThat(changed.status()).isEqualTo("REVOKED");
        assertThat(changed.summary().get("ko")).contains("400건");
        assertThat(changed.validUntilMinutes()).as("a revoked one runs long enough to hold the revocation").isEqualTo(43_140L);
        assertThat(AgentCasesController.delegationOf(new DelegationChoice(null, "EXPIRED", null).applyTo(base))
                .validUntilMinutes()).isEqualTo(-120L);
        assertThat(AgentCasesController.delegationOf(catalog.find("N1").orElseThrow()).maxItemsPerRequest())
                .as("a delegation that states no limit").isNull();
    }

    /**
     * AS-12: the case view carries the visitor's choice: the delegation shown before the run is the one the run will
     * execute, computed by the server from the fixed lists; a value outside them, or a choice on another case, is refused.
     */
    @Test
    void theCaseViewCarriesTheVisitorsChoiceOfTheEditableCaseAndRefusesAnyOther() throws Exception {
        AgentCasesController controller = new AgentCasesController(new AgentTaskCatalog(JSON),
                new StaticListableBeanFactory().getBeanProvider(RunStore.class), JSON);

        AgentCasesController.AgentCaseView own = controller.agentCase("ED1", null, null, null).getBody();
        AgentCasesController.AgentCaseView changed = controller.agentCase("ED1", 400, "EXPIRED", "READ_ONLY").getBody();

        assertThat(own.delegation().maxItemsPerRequest()).isEqualTo(40);
        assertThat(own.delegation().operations()).contains("EXPORT");
        assertThat(changed.delegation().maxItemsPerRequest()).isEqualTo(400);
        assertThat(changed.delegation().validUntilMinutes()).isEqualTo(-120L);
        assertThat(changed.delegation().operations()).doesNotContain("EXPORT");
        assertThat(changed.classification()).as("what the case is called follows the change").isEqualTo("THREAT");
        assertThat(controller.agentCase("ED1", 400, "VALID", "READ_EXPORT").getBody().classification())
                .isEqualTo("NORMAL");
        assertThat(controller.agentCase("ED1", 41, null, null).getStatusCode().value()).isEqualTo(400);
        assertThat(controller.agentCase("ED1", null, "FOREVER", null).getStatusCode().value()).isEqualTo(400);
        assertThat(controller.agentCase("ED1", null, null, "ALL").getStatusCode().value()).isEqualTo(400);
        assertThat(controller.agentCase("T5", 400, null, null).getStatusCode().value())
                .as("another case takes no choice").isEqualTo(400);
        assertThat(controller.agentCase("T5", null, null, null).getStatusCode().value()).isEqualTo(200);
        assertThat(controller.agentCase("ED1").getBody().delegation().maxItemsPerRequest()).isEqualTo(40);
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
        // a person scenario is no agent case: it is not found here (its key has the shape of a case key since AS-14)
        assertThat(controller.agentCase("S13").getStatusCode().value()).isEqualTo(404);
        assertThat(controller.agentCase("T99").getStatusCode().value()).isEqualTo(404);
        assertThat(controller.agentRun("run-0123456789ab").getStatusCode().value()).isEqualTo(404);
    }
}
