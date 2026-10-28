package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.combination.Combination;
import io.contexa.showcase.portal.combination.CombinationCatalog;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent Agent중심-화면 AS-6: the live configuration tells each case's subject, PERSON or AGENT, so the lab can
 * separate the two entrances; the other fields of an option are as they were.
 */
class ScenarioOptionSubjectTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    private ScenarioDefinition agentTask() throws IOException {
        try (InputStream stream = ScenarioOptionSubjectTest.class.getResourceAsStream("/agent-tasks/T5.json")) {
            return json.readValue(stream, ScenarioDefinition.class);
        }
    }

    @Test
    void aCaseWhoseWorkAnAgentDoesIsAnAgentCase() throws IOException {
        ScenarioDefinition agent = agentTask();

        LiveController.ScenarioOption option = LiveController.ScenarioOption.of(agent);

        assertThat(option.subject()).isEqualTo("AGENT");
        assertThat(option.key()).isEqualTo(agent.key());
        assertThat(option.title()).isEqualTo(agent.title());
        assertThat(option.classification()).isEqualTo(agent.oracle().classification());
    }

    @Test
    void theOpenAgentCasesAreListedApartFromTheScenariosEachAsAnAgentOption() throws IOException {
        AgentTaskCatalog catalog = new AgentTaskCatalog(json);

        List<LiveController.ScenarioOption> options = LiveController.openAgentCases(catalog, List.of("T5"));

        assertThat(options).singleElement().satisfies(option -> {
            assertThat(option.key()).isEqualTo("T5");
            assertThat(option.subject()).isEqualTo("AGENT");
            assertThat(option.title()).containsKeys("ko", "en");
        });
        assertThat(LiveController.openAgentCases(catalog, List.of())).isEmpty();
    }

    @Test
    void aCaseOfAPersonIsAPersonCase() {
        ScenarioDefinition person = CombinationCatalog.scenario(Combination.parse("adm-a.DAWN.4831.MATCH.USUAL"));

        assertThat(LiveController.ScenarioOption.of(person).subject()).isEqualTo("PERSON");
    }
}
