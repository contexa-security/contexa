package io.contexa.showcase.portal.agent;

import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.agent.AgentWork.Answer;
import io.contexa.showcase.portal.agent.AgentWork.Request;
import io.contexa.showcase.portal.agent.AgentWork.ToolCall;
import org.junit.jupiter.api.Test;
import org.springframework.ai.support.ToolCallbacks;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A7-2b: the business agent's tools send what the agent asks and give back control D's answer. */
class BusinessAgentToolsTest {

    private final List<Request> sent = new ArrayList<>();

    private AgentWork.Sender answering(String body) {
        return request -> {
            sent.add(request);
            return new Answer(sent.size(), "/path", 200, "DELIVERED", null, body, Map.of("D", "DELIVERED"),
                    Map.of("D", 0), Map.of());
        };
    }

    @Test
    void everyToolSendsTheBusinessRequestTheAgentAskedFor() {
        BusinessAgentTools tools = new BusinessAgentTools(answering("{}"), 20);

        tools.listProjects();
        tools.listDocuments("HX-310", "DRAWING", "rotor");
        tools.readDocument("DOC-7");
        tools.downloadDocument("DOC-8");
        tools.exportDocuments("GB-500", 40);
        tools.readCustomer("CUS-0001");
        tools.grantRole("HX-310", "E-0042", "REVIEW");

        assertThat(sent).containsExactly(
                new Request(BusinessOperation.PROJECT_LIST, null, null, null, null, null, null, null, null),
                new Request(BusinessOperation.DOCUMENT_LIST, "HX-310", null, null, null, "DRAWING", "rotor", null, null),
                new Request(BusinessOperation.DOCUMENT_READ, null, "DOC-7", null, null, null, null, null, null),
                new Request(BusinessOperation.DOCUMENT_DOWNLOAD, null, "DOC-8", null, null, null, null, null, null),
                new Request(BusinessOperation.EXPORT, "GB-500", null, null, 40, null, null, null, null),
                new Request(BusinessOperation.CUSTOMER_READ, null, null, "CUS-0001", null, null, null, null, null),
                new Request(BusinessOperation.ROLE_GRANT, "HX-310", null, null, null, null, null, "E-0042", "REVIEW"));
        assertThat(tools.calls()).extracting(ToolCall::tool).containsExactly("listProjects", "listDocuments",
                "readDocument", "downloadDocument", "exportDocuments", "readCustomer", "grantRole");
        assertThat(tools.calls()).allMatch(ToolCall::sent);
        assertThat(tools.calls().get(1).arguments()).containsExactly(Map.entry("projectKey", "HX-310"),
                Map.entry("type", "DRAWING"), Map.entry("titleWords", "rotor"));
        assertThat(tools.budgetUsed()).isFalse();
    }

    @Test
    void theAgentReceivesControlDsAnswerCutAtTheLimit() {
        String body = "x".repeat(BusinessAgentTools.ANSWER_LIMIT + 10);
        BusinessAgentTools tools = new BusinessAgentTools(answering(body), 5);

        String result = tools.readDocument("DOC-1");

        assertThat(result).startsWith("HTTP 200\n" + "x".repeat(BusinessAgentTools.ANSWER_LIMIT))
                .endsWith("[cut at " + BusinessAgentTools.ANSWER_LIMIT + " characters]");
        assertThat(tools.calls().get(0).answer().body()).as("the record keeps D's answer whole").isEqualTo(body);
    }

    @Test
    void pastItsBudgetOrItsTimeTheWorkSendsNothingMore() {
        BusinessAgentTools tools = new BusinessAgentTools(answering("{}"), 2);

        tools.listProjects();
        tools.readDocument("DOC-1");
        String third = tools.readDocument("DOC-2");

        assertThat(sent).hasSize(2);
        assertThat(third).contains("budget");
        assertThat(tools.budgetUsed()).isTrue();
        assertThat(tools.calls()).extracting(ToolCall::sent).containsExactly(true, true, false);

        BusinessAgentTools timed = new BusinessAgentTools(answering("{}"), 5);
        timed.stop();
        assertThat(timed.readDocument("DOC-3")).contains("time");
        assertThat(timed.calls()).singleElement().satisfies(call -> assertThat(call.sent()).isFalse());
        assertThat(sent).hasSize(2);
    }

    @Test
    void aRequestThatCouldNotBeSentIsRecordedAsNotSent() {
        BusinessAgentTools tools = new BusinessAgentTools(request -> {
            throw new IOException("connection refused");
        }, 5);

        assertThat(tools.readDocument("DOC-1")).contains("connection refused");
        assertThat(tools.calls()).singleElement().satisfies(call -> {
            assertThat(call.sent()).isFalse();
            assertThat(call.answer()).isNull();
        });
    }

    @Test
    void theToolsTheAgentSeesAreTheOnesEachOperationMapsTo() {
        BusinessAgentTools tools = new BusinessAgentTools(answering("{}"), 5);

        assertThat(Arrays.stream(ToolCallbacks.from(tools)).map(callback -> callback.getToolDefinition().name()))
                .containsExactlyInAnyOrderElementsOf(BusinessAgentTools.TOOL_OF_OPERATION.values());
    }
}
