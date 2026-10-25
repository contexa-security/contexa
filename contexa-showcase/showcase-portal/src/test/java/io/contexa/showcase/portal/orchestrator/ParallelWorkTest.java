package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.agent.AgentTaskProof;
import io.contexa.showcase.portal.agent.AgentWork.Answer;
import io.contexa.showcase.portal.agent.AgentWork.Request;
import io.contexa.showcase.portal.agent.AgentWork.ToolCall;
import io.contexa.showcase.portal.agent.AgentWork.Transcript;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A6-R2: requests that other workers send beside the agent with the same credentials (a second runtime using
 * the token, or the same request many times before a decision exists) are requests of the work like the agent's own.
 */
class ParallelWorkTest {

    private static final List<String> CONTROLS = List.of("A", "B", "C1", "C2", "D");
    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    @Test
    void aParallelRequestIsACallOfTheWorkThatTheProofCountsLikeTheAgentsOwn() {
        Request export = new Request(BusinessOperation.EXPORT, "HX-310", null, null, 40, null, null, null, null);
        Map<String, String> delivered = Map.of("A", "DELIVERED", "B", "DELIVERED", "C1", "DELIVERED", "C2", "DELIVERED",
                "D", "REFUSED");
        Answer answer = new Answer(7, "/api/projects/HX-310/exports?items=40", 401, "REFUSED", "ZERO_TRUST_CHALLENGE",
                "{}", delivered, Map.of("A", 40, "B", 40, "C1", 40, "C2", 40, "D", 0), Map.of());

        ToolCall call = RunOrchestrator.parallelCall(3, export, answer, "parallel 2 of 4");

        assertThat(call.tool()).isEqualTo("exportDocuments");
        assertThat(call.arguments()).containsEntry("projectKey", "HX-310").containsEntry("items", 40)
                .containsEntry("worker", "parallel 2 of 4");
        assertThat(call.sent()).isTrue();
        ScenarioDefinition.AgentTask task = new ScenarioDefinition.AgentTask(Map.of("en", "work"), null,
                ScenarioDefinition.Sender.DELEGATED_AGENT, null, null, null, List.of(),
                new ScenarioDefinition.AgentTask.Proof(null, List.of("HX-310")));
        Transcript work = new Transcript("model", "prompt", "work", List.of(call), "answer", "ANSWERED", null,
                Map.of(), Instant.parse("2026-10-24T14:00:00Z"), Instant.parse("2026-10-24T14:00:30Z"));

        AgentTaskProof.Proof proof = AgentTaskProof.of(task, work, CONTROLS);

        assertThat(proof.attempts()).isEqualTo(1);
        assertThat(proof.controls().get("A").items()).isEqualTo(40);
        assertThat(proof.controls().get("D").items()).isZero();
        assertThat(proof.controls().get("D").firstStopOutcome()).isEqualTo("REFUSED");
    }

    @Test
    void parallelWorkIsDefinedByTheCaseAndFollowsItToEveryPath() throws IOException {
        ObjectNode tree = (ObjectNode) json.readTree(read("N3"));
        ObjectNode task = (ObjectNode) tree.get("task");
        task.putArray("paths").add("DELEGATED_AGENT").add("AGENT_SESSION");
        ArrayNode parallel = task.putArray("parallel");
        ObjectNode work = parallel.addObject();
        work.put("startAfterToolCalls", 2).put("copies", 3);
        work.putObject("runtime").put("network", "203.0.113.0/24").put("userAgent", "python-httpx/0.27.2");
        work.putArray("requests").addObject().put("operation", "DOCUMENT_LIST").put("project", "HX-310");
        ScenarioDefinition measured = json.treeToValue(tree, ScenarioDefinition.class);

        ScenarioDefinition onSession = measured.onPath(ScenarioDefinition.Sender.AGENT_SESSION);

        assertThat(onSession.task().parallel()).singleElement().satisfies(found -> {
            assertThat(found.startAfterToolCalls()).isEqualTo(2);
            assertThat(found.copies()).isEqualTo(3);
            assertThat(found.runtime().userAgent()).isEqualTo("python-httpx/0.27.2");
            assertThat(found.requests()).singleElement().satisfies(request -> {
                assertThat(request.operation()).isEqualTo(BusinessOperation.DOCUMENT_LIST);
                assertThat(request.project()).isEqualTo("HX-310");
            });
        });
        ScenarioDefinition plain = json.readValue(read("N3"), ScenarioDefinition.class);
        assertThat(plain.task().parallel()).isNull();
        assertThat(json.writeValueAsString(plain.task())).as("a case without parallel work serializes as before")
                .doesNotContain("parallel");
    }

    private static byte[] read(String key) throws IOException {
        try (InputStream stream = ParallelWorkTest.class.getResourceAsStream("/agent-tasks/" + key + ".json")) {
            assertThat(stream).isNotNull();
            return stream.readAllBytes();
        }
    }
}
