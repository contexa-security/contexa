package io.contexa.showcase.portal.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.agent.AgentWork.Answer;
import io.contexa.showcase.portal.agent.AgentWork.Transcript;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent A7-2b: the business agent's real Spring AI loop against a model server that answers as OpenAI's chat API
 * does: the model asks for a tool, the tool sends the request, the model receives control D's answer and answers.
 * No model is called.
 */
class BusinessAgentTest {

    private static final String TOOL_CALL = """
            {"id":"c-1","object":"chat.completion","created":1,"model":"gpt-6-luna","choices":[{"index":0,
            "message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function",
            "function":{"name":"readDocument","arguments":"{\\"documentKey\\":\\"DOC-7\\"}"}}]},
            "finish_reason":"tool_calls"}],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110}}""";
    private static final String FINAL = """
            {"id":"c-2","object":"chat.completion","created":2,"model":"gpt-6-luna","choices":[{"index":0,
            "message":{"role":"assistant","content":"The rotor drawing is revision 3."},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":200,"completion_tokens":20,"total_tokens":220}}""";

    private final ObjectMapper json = new ObjectMapper();
    private final List<JsonNode> modelRequests = Collections.synchronizedList(new ArrayList<>());
    private final CountDownLatch release = new CountDownLatch(1);
    private HttpServer server;

    @AfterEach
    void stopTheModelServer() {
        release.countDown();
        if (server != null) {
            server.stop(0);
        }
    }

    private String modelServer(List<String> answers, Duration delay) throws IOException {
        return modelServer("/v1/chat/completions", answers, delay);
    }

    private String modelServer(String path, List<String> answers, Duration delay) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(path, exchange -> {
            JsonNode request = json.readTree(exchange.getRequestBody().readAllBytes());
            int number;
            synchronized (modelRequests) {
                modelRequests.add(request);
                number = modelRequests.size();
            }
            if (!delay.isZero()) {
                try {
                    release.await(delay.toMillis(), TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            byte[] body = answers.get(Math.min(number, answers.size()) - 1).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static AgentWork.Sender controlD(List<AgentWork.Request> sent) {
        return request -> {
            sent.add(request);
            return new Answer(sent.size(), "/api/documents/" + request.document(), 200, "DELIVERED", null,
                    "{\"documentKey\":\"DOC-7\",\"projectKey\":\"HX-310\",\"revision\":\"3\"}",
                    Map.of("D", "DELIVERED"), Map.of("D", 0), Map.of());
        };
    }

    @Test
    void theAgentCallsTheToolTheModelAsksForAndAnswersWithWhatControlDReturned() throws IOException {
        String baseUrl = modelServer(List.of(TOOL_CALL, FINAL), Duration.ZERO);
        List<AgentWork.Request> sent = new ArrayList<>();
        BusinessAgentTools tools = new BusinessAgentTools(controlD(sent), 5);
        BusinessAgent agent = new BusinessAgent(new AgentModels("test-key", baseUrl, "gpt-6-luna", "none"));

        Transcript work = agent.run("gpt-6-luna", BusinessAgent.DEFAULT_PROMPT, "Which revision is the rotor drawing?",
                tools, Set.of("listDocuments", "readDocument"), Duration.ofSeconds(30));

        assertThat(work.stopReason()).isEqualTo("ANSWERED");
        assertThat(work.finalAnswer()).isEqualTo("The rotor drawing is revision 3.");
        assertThat(sent).singleElement().satisfies(request -> {
            assertThat(request.operation()).isEqualTo(BusinessOperation.DOCUMENT_READ);
            assertThat(request.document()).isEqualTo("DOC-7");
        });
        assertThat(work.toolCalls()).singleElement().satisfies(call -> {
            assertThat(call.tool()).isEqualTo("readDocument");
            assertThat(call.result()).startsWith("HTTP 200\n{\"documentKey\":\"DOC-7\"");
        });
        assertThat(work.usage()).as("summed over both rounds").containsEntry("totalTokens", 330);

        assertThat(modelRequests).hasSize(2);
        JsonNode first = modelRequests.get(0);
        assertThat(first.path("model").asText()).isEqualTo("gpt-6-luna");
        assertThat(first.path("parallel_tool_calls").asBoolean(true)).isFalse();
        assertThat(first.has("temperature")).as("the model's own default").isFalse();
        assertThat(first.path("reasoning_effort").asText()).as("function tools on chat completions").isEqualTo("none");
        List<String> offered = new ArrayList<>();
        first.path("tools").forEach(tool -> offered.add(tool.path("function").path("name").asText()));
        assertThat(offered).as("only the tools the work offers").containsExactlyInAnyOrder("listDocuments",
                "readDocument");
        assertThat(first.path("messages").get(0).path("content").asText()).isEqualTo(BusinessAgent.DEFAULT_PROMPT);
        JsonNode toolAnswer = modelRequests.get(1).path("messages").get(3);
        assertThat(toolAnswer.path("role").asText()).isEqualTo("tool");
        assertThat(toolAnswer.path("content").asText()).contains("HTTP 200").contains("HX-310");
    }

    /** docs/agent 위임결정기록 DD-4: the same work on Anthropic's messages API when the OpenAI balance is used up. */
    @Test
    void onAnthropicTheAgentCallsTheToolOneAtATimeAndAnswers() throws IOException {
        String toolUse = "{\"id\":\"msg-1\",\"type\":\"message\",\"role\":\"assistant\","
                + "\"model\":\"claude-haiku-5-5\",\"content\":[{\"type\":\"tool_use\",\"id\":\"toolu-1\","
                + "\"name\":\"readDocument\",\"input\":{\"documentKey\":\"DOC-7\"}}],"
                + "\"stop_reason\":\"tool_use\",\"stop_sequence\":null,"
                + "\"usage\":{\"input_tokens\":100,\"output_tokens\":10}}";
        String answer = "{\"id\":\"msg-2\",\"type\":\"message\",\"role\":\"assistant\","
                + "\"model\":\"claude-haiku-5-5\",\"content\":[{\"type\":\"text\","
                + "\"text\":\"The rotor drawing is revision 3.\"}],\"stop_reason\":\"end_turn\","
                + "\"stop_sequence\":null,\"usage\":{\"input_tokens\":200,\"output_tokens\":20}}";
        String baseUrl = modelServer("/v1/messages", List.of(toolUse, answer), Duration.ZERO);
        List<AgentWork.Request> sent = new ArrayList<>();
        BusinessAgentTools tools = new BusinessAgentTools(controlD(sent), 5);
        BusinessAgent agent = new BusinessAgent(new AgentModels(AgentModels.ANTHROPIC, "test-key", baseUrl,
                "claude-haiku-5-5", "none"));

        Transcript work = agent.run("claude-haiku-5-5", BusinessAgent.DEFAULT_PROMPT,
                "Which revision is the rotor drawing?", tools, Set.of("listDocuments", "readDocument"),
                Duration.ofSeconds(30));

        assertThat(work.stopReason()).isEqualTo("ANSWERED");
        assertThat(work.finalAnswer()).isEqualTo("The rotor drawing is revision 3.");
        assertThat(sent).singleElement().satisfies(request -> assertThat(request.document()).isEqualTo("DOC-7"));
        assertThat(modelRequests).hasSize(2);
        JsonNode first = modelRequests.get(0);
        assertThat(first.path("model").asText()).isEqualTo("claude-haiku-5-5");
        assertThat(first.path("max_tokens").asInt()).isEqualTo(AgentModels.ANTHROPIC_MAX_TOKENS);
        assertThat(first.path("tool_choice").path("disable_parallel_tool_use").asBoolean()).isTrue();
        assertThat(first.path("system").toString()).contains("business agent of an employee");
        List<String> offered = new ArrayList<>();
        first.path("tools").forEach(tool -> offered.add(tool.path("name").asText()));
        assertThat(offered).containsExactlyInAnyOrder("listDocuments", "readDocument");
        assertThat(modelRequests.get(1).toString()).contains("tool_result").contains("HTTP 200").contains("HX-310");
    }

    @Test
    void anUnknownProviderIsRefused() {
        assertThatThrownBy(() -> new AgentModels("gemini", "key", null, "model", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(new AgentModels(AgentModels.ANTHROPIC, "", null, "claude-haiku-5-5", null).provider())
                .isEqualTo(AgentModels.ANTHROPIC);
    }

    @Test
    void workPastItsTimeLimitStopsAndSendsNothingMore() throws IOException {
        String baseUrl = modelServer(List.of(TOOL_CALL, FINAL), Duration.ofSeconds(10));
        List<AgentWork.Request> sent = new ArrayList<>();
        BusinessAgentTools tools = new BusinessAgentTools(controlD(sent), 5);
        BusinessAgent agent = new BusinessAgent(new AgentModels("test-key", baseUrl, "gpt-6-luna", "none"));

        Transcript work = agent.run("gpt-6-luna", BusinessAgent.DEFAULT_PROMPT, "work", tools,
                Set.of("readDocument"), Duration.ofMillis(500));

        assertThat(work.stopReason()).isEqualTo("TIME_LIMIT");
        assertThat(work.finalAnswer()).isNull();
        release.countDown();
        assertThat(tools.readDocument("DOC-1")).contains("time");
        assertThat(sent).isEmpty();
    }

    @Test
    void withoutAModelKeyTheWorkFailsWithThatReason() {
        BusinessAgentTools tools = new BusinessAgentTools(controlD(new ArrayList<>()), 5);
        BusinessAgent agent = new BusinessAgent(new AgentModels("", null, "gpt-6-luna", "none"));

        Transcript work = agent.run("gpt-6-luna", BusinessAgent.DEFAULT_PROMPT, "work", tools, Set.of("readDocument"),
                Duration.ofSeconds(5));

        assertThat(work.stopReason()).isEqualTo("FAILED");
        assertThat(work.failure()).contains("OPENAI_API_KEY");
        assertThat(work.toolCalls()).isEmpty();
    }
}
