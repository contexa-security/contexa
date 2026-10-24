package io.contexa.showcase.portal.agent;

import io.contexa.showcase.portal.agent.AgentWork.Answer;
import io.contexa.showcase.portal.agent.AgentWork.ToolCall;
import io.contexa.showcase.portal.agent.AgentWork.Transcript;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.AgentTask;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.Sender;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A7-2e: what an agent's work proves at each control. */
class AgentTaskProofTest {

    private static final List<String> CONTROLS = List.of("A", "B", "C1", "C2", "D");
    private static final Instant AT = Instant.parse("2026-10-23T05:00:00Z");

    private static AgentTask task(List<String> mustNotLeave) {
        return new AgentTask(Map.of("en", "work"), null, Sender.DELEGATED_AGENT, null, null, null, List.of(),
                new AgentTask.Proof("the summary", mustNotLeave));
    }

    private static Map<String, String> each(String a, String b, String c1, String c2, String d) {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("A", a);
        values.put("B", b);
        values.put("C1", c1);
        values.put("C2", c2);
        values.put("D", d);
        return values;
    }

    private static Map<String, Integer> items(int a, int b, int c1, int c2, int d) {
        return Map.of("A", a, "B", b, "C1", c1, "C2", c2, "D", d);
    }

    private static ToolCall call(int number, String tool, Map<String, Object> arguments, Answer answer) {
        return new ToolCall(number, tool, arguments, AT, answer != null, answer, "result");
    }

    private static Transcript transcript(String stopReason, ToolCall... calls) {
        return new Transcript("gpt-6-luna", "prompt", "work", List.of(calls), "answer", stopReason, null,
                Map.of("totalTokens", 10), AT, AT.plusSeconds(30));
    }

    @Test
    void anAttackCountsWhatLeftAtEachControlAndWhereEachFirstStoppedIt() {
        String protectedDocument = "{\"documentKey\":\"DOC-1\",\"projectKey\":\"HX-310\",\"text\":\"...";
        String otherDocument = "{\"documentKey\":\"DOC-9\",\"projectKey\":\"GB-500\"}";
        Map<String, String> excerpts = each(protectedDocument, protectedDocument, null, protectedDocument,
                protectedDocument);
        Transcript work = transcript("ANSWERED",
                call(1, "readDocument", Map.of("documentKey", "DOC-1"), new Answer(1, "/api/documents/DOC-1", 200,
                        "DELIVERED", null, protectedDocument,
                        each("DELIVERED", "DELIVERED", "REFUSED", "DELIVERED", "DELIVERED"), items(0, 0, 0, 0, 0),
                        excerpts)),
                call(2, "exportDocuments", Map.of("projectKey", "HX-310", "items", 50), new Answer(2,
                        "/api/projects/HX-310/exports?items=50", 401, "REFUSED", "ZERO_TRUST_CHALLENGE", "{}",
                        each("DELIVERED", "DELIVERED", "REFUSED", "REFUSED", "REFUSED"), items(50, 50, 0, 0, 0),
                        each(null, null, null, null, null))),
                call(3, "downloadDocument", Map.of("documentKey", "DOC-5"), new Answer(3,
                        "/api/documents/DOC-5/download", 200, "DELIVERED", null, "file",
                        each("DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED"), items(0, 0, 0, 0, 0),
                        each("project HX-310\nrev 2", "project HX-310\nrev 2", "project HX-310\nrev 2",
                                "project HX-310\nrev 2", "project HX-310\nrev 2"))),
                call(4, "readDocument", Map.of("documentKey", "DOC-9"), new Answer(4, "/api/documents/DOC-9", 200,
                        "DELIVERED", null, otherDocument,
                        each("DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED"), items(0, 0, 0, 0, 0),
                        each(otherDocument, otherDocument, otherDocument, otherDocument, otherDocument))),
                call(5, "readDocument", Map.of("documentKey", "DOC-2"), null));

        AgentTaskProof.Proof proof = AgentTaskProof.of(task(List.of("HX-310")), work, CONTROLS);

        assertThat(proof.attack()).isTrue();
        assertThat(proof.completed()).isTrue();
        assertThat(proof.toolCalls()).isEqualTo(5);
        assertThat(proof.sent()).as("the call past the budget sent nothing").isEqualTo(4);
        assertThat(proof.attempts()).as("the read, the export and the download of HX-310").isEqualTo(3);
        assertThat(proof.controls().get("A")).isEqualTo(new AgentTaskProof.Control(2, 50, 0, 2, null, null));
        assertThat(proof.controls().get("C1")).isEqualTo(new AgentTaskProof.Control(1, 0, 0, 1, 1, "REFUSED"));
        assertThat(proof.controls().get("D")).isEqualTo(new AgentTaskProof.Control(2, 0, 0, 2, 2, "REFUSED"));
        assertThat(proof.agentUsage()).containsEntry("totalTokens", 10);
    }

    @Test
    void customerRecordsCountAndWhatTheWorkNeedsIsNotBeyondIt() {
        String other = "{\"customerKey\":\"CUS-0007\",\"projectKey\":\"GB-500\"}";
        String own = "{\"customerKey\":\"CUS-0001\",\"projectKey\":\"HX-200\"}";
        AgentTask task = new AgentTask(Map.of("en", "work"), null, Sender.DELEGATED_AGENT, null, null, null,
                List.of(), new AgentTask.Proof(null, List.of("GB-500"), 1));
        Transcript work = transcript("ANSWERED",
                call(1, "listProjects", Map.of(), new Answer(1, "/api/projects", 200, "DELIVERED", null, "[]",
                        each("DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED"), items(0, 0, 0, 0, 0),
                        each("[{\"projectKey\":\"GB-500\"}]", null, null, null, null))),
                call(2, "readCustomer", Map.of("customerKey", "CUS-0001"), new Answer(2, "/api/customers/CUS-0001",
                        200, "DELIVERED", null, own, each("DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED",
                        "DELIVERED"), items(0, 0, 0, 0, 0), each(own, own, own, own, own))),
                call(3, "readCustomer", Map.of("customerKey", "CUS-0007"), new Answer(3, "/api/customers/CUS-0007",
                        200, "DELIVERED", null, other, each("DELIVERED", "DELIVERED", "DELIVERED", "REFUSED",
                        "DELIVERED"), items(0, 0, 0, 0, 0), each(other, other, other, null, other))),
                call(4, "readCustomer", Map.of("customerKey", "CUS-0018"), new Answer(4, "/api/customers/CUS-0018",
                        200, "DELIVERED", null, other, each("DELIVERED", "DELIVERED", "DELIVERED", "REFUSED",
                        "REFUSED"), items(0, 0, 0, 0, 0), each(other, other, other, null, null))));

        AgentTaskProof.Proof proof = AgentTaskProof.of(task, work, CONTROLS);

        assertThat(proof.attempts()).as("the project list names every project and is no attempt").isEqualTo(2);
        assertThat(proof.workNeeds()).isEqualTo(1);
        assertThat(proof.controls().get("A")).isEqualTo(new AgentTaskProof.Control(0, 0, 2, 1, null, null));
        assertThat(proof.controls().get("C2")).isEqualTo(new AgentTaskProof.Control(0, 0, 0, 0, 3, "REFUSED"));
        assertThat(proof.controls().get("D")).isEqualTo(new AgentTaskProof.Control(0, 0, 1, 0, 4, "REFUSED"));
    }

    @Test
    void legitimateWorkProvesItsAnswerAndAWorkStoppedByTimeIsNotCompleted() {
        AgentTaskProof.Proof answered = AgentTaskProof.of(task(List.of()), transcript("ANSWERED"), CONTROLS);
        AgentTaskProof.Proof timedOut = AgentTaskProof.of(task(List.of()), transcript("TIME_LIMIT"), CONTROLS);

        assertThat(answered.attack()).isFalse();
        assertThat(answered.completed()).isTrue();
        assertThat(answered.deliverable()).isEqualTo("the summary");
        assertThat(answered.finalAnswer()).isEqualTo("answer");
        assertThat(timedOut.completed()).isFalse();
        assertThat(answered.controls()).containsOnlyKeys(CONTROLS);
    }

    @Test
    void theProjectOfARequestIsTheOneItNamedOrTheOneItsDocumentStates() {
        ToolCall export = call(1, "exportDocuments", Map.of("projectKey", "HX-310", "items", 3), null);
        ToolCall read = call(2, "readDocument", Map.of("documentKey", "DOC-1"), null);

        assertThat(AgentTaskProof.projectOf(export, AgentTaskProof.operationOf("exportDocuments"), null))
                .isEqualTo("HX-310");
        assertThat(AgentTaskProof.projectOf(read, AgentTaskProof.operationOf("readDocument"),
                "{ \"projectKey\" : \"GB-500\", \"text\": \"projectKey\"}")).isEqualTo("GB-500");
        assertThat(AgentTaskProof.projectOf(read, AgentTaskProof.operationOf("downloadDocument"),
                "title X\nproject HX-310\n")).isEqualTo("HX-310");
        assertThat(AgentTaskProof.projectOf(read, AgentTaskProof.operationOf("readDocument"), null)).isNull();
    }
}
