package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent A6-R0: a measurement sends an agent case on one of the paths it is measured on; the case's agent sends
 * its work and its steps that way, the person's steps stay, and a path the case is not measured on is refused.
 */
class AgentPathsTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    @Test
    void aCaseOnAnotherPathSendsItsAgentsWorkAndStepsThatWayAndThePersonsStepsStay() throws IOException {
        ObjectNode tree = (ObjectNode) json.readTree(read("N3"));
        ((ObjectNode) tree.get("task")).putArray("paths").add("DELEGATED_AGENT").add("AGENT_SESSION");
        ScenarioDefinition measured = json.treeToValue(tree, ScenarioDefinition.class);

        ScenarioDefinition onSession = measured.onPath(AgentPaths.sender("session"));

        assertThat(onSession.task().sender()).isEqualTo(ScenarioDefinition.Sender.AGENT_SESSION);
        assertThat(onSession.steps()).hasSameSizeAs(measured.steps());
        for (int i = 0; i < measured.steps().size(); i++) {
            ScenarioDefinition.Sender before = measured.steps().get(i).senderOrPerson();
            ScenarioDefinition.Sender after = onSession.steps().get(i).senderOrPerson();
            assertThat(after).isEqualTo(before == ScenarioDefinition.Sender.PERSON ? ScenarioDefinition.Sender.PERSON
                    : ScenarioDefinition.Sender.AGENT_SESSION);
        }
        assertThat(measured.steps()).extracting(ScenarioDefinition.Step::senderOrPerson)
                .contains(ScenarioDefinition.Sender.PERSON, ScenarioDefinition.Sender.DELEGATED_AGENT);
        assertThat(measured.onPath(ScenarioDefinition.Sender.DELEGATED_AGENT)).isSameAs(measured);
        assertThatThrownBy(() -> measured.onPath(AgentPaths.sender("OAUTH2_AGENT")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aCaseWithoutPathsIsMeasuredOnItsOwnPathAndUnknownPathsAreRefused() throws IOException {
        ScenarioDefinition n3 = json.readValue(read("N3"), ScenarioDefinition.class);

        assertThat(n3.task().measuredPaths()).containsExactly(ScenarioDefinition.Sender.DELEGATED_AGENT);
        assertThatThrownBy(() -> n3.onPath(ScenarioDefinition.Sender.AGENT_SESSION))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AgentPaths.sender("TOKEN")).isInstanceOf(IllegalArgumentException.class);
        assertThat(AgentPaths.name(ScenarioDefinition.Sender.AUTONOMOUS_AGENT)).isEqualTo("OAUTH2_AGENT");
    }

    private static byte[] read(String key) throws IOException {
        try (InputStream stream = AgentPathsTest.class.getResourceAsStream("/agent-tasks/" + key + ".json")) {
            assertThat(stream).isNotNull();
            return stream.readAllBytes();
        }
    }
}
