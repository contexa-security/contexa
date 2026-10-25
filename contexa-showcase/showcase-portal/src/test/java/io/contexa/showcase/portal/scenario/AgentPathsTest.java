package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
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

    /**
     * docs/agent A6-R3, A6-R7: the headers an agent's runtime adds and the administrator's actions while it works follow
     * the work to the path it is sent on; an action falls on the paths it names, on all when it names none; a case
     * without them serializes as it did before (its definition hash is unchanged).
     */
    @Test
    void claimHeadersAndAdministratorActionsFollowTheWorkAndFallOnTheirOwnPaths() throws IOException {
        ObjectNode tree = (ObjectNode) json.readTree(read("N3"));
        ObjectNode task = (ObjectNode) tree.get("task");
        task.putArray("paths").add("DELEGATED_AGENT").add("AGENT_SESSION");
        task.putObject("headers").put("X-Contexa-Agent-Id", "agt-other");
        ArrayNode actions = task.putArray("adminActions");
        actions.addObject().put("afterToolCalls", 4).put("action", "REVOKE_DELEGATION").put("reason", "r")
                .putArray("paths").add("DELEGATED_AGENT");
        actions.addObject().put("afterToolCalls", 5).put("action", "STOP_AGENT").put("reason", "r")
                .putArray("paths").add("AGENT_SESSION");
        actions.addObject().put("afterToolCalls", 6).put("action", "STOP_AGENT").put("reason", "r");
        ScenarioDefinition measured = json.treeToValue(tree, ScenarioDefinition.class);

        ScenarioDefinition onSession = measured.onPath(AgentPaths.sender("session"));

        assertThat(onSession.task().headers()).containsEntry("X-Contexa-Agent-Id", "agt-other");
        assertThat(onSession.task().adminActionsOn(ScenarioDefinition.Sender.AGENT_SESSION))
                .extracting(ScenarioDefinition.AgentTask.AdminAction::afterToolCalls).containsExactly(5, 6);
        assertThat(measured.task().adminActionsOn(ScenarioDefinition.Sender.DELEGATED_AGENT))
                .extracting(ScenarioDefinition.AgentTask.AdminAction::afterToolCalls).containsExactly(4, 6);
        assertThat(measured.task().adminActionsOn(ScenarioDefinition.Sender.AUTONOMOUS_AGENT))
                .extracting(ScenarioDefinition.AgentTask.AdminAction::afterToolCalls).containsExactly(6);

        ScenarioDefinition plain = json.readValue(read("N3"), ScenarioDefinition.class);
        assertThat(plain.task().headers()).isNull();
        assertThat(plain.task().adminActionsOn(ScenarioDefinition.Sender.DELEGATED_AGENT)).isEmpty();
        assertThat(json.writeValueAsString(plain.task())).doesNotContain("headers").doesNotContain("adminActions");
    }

    private static byte[] read(String key) throws IOException {
        try (InputStream stream = AgentPathsTest.class.getResourceAsStream("/agent-tasks/" + key + ".json")) {
            assertThat(stream).isNotNull();
            return stream.readAllBytes();
        }
    }
}
