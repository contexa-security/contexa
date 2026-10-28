package io.contexa.showcase.portal.agent;

import io.contexa.showcase.portal.agent.AgentWork.Transcript;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.metadata.Usage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.support.ToolCallbacks;
import org.springframework.ai.tool.ToolCallback;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

/**
 * docs/agent A7-2b: a business agent doing the work a person gave it: a Spring AI chat client with the company's tools,
 * asked once with the person's instruction, calling the tools as it decides until it answers. The work stops at its
 * time limit; past its tool budget the tools send nothing more. The agent's instruction is a plain business agent's
 * (a case that tampers with it gives its own): the agent holds no security of its own, so what it does is what
 * Contexa sees and decides on.
 */
public class BusinessAgent {

    /** The business agent's own instruction. */
    public static final String DEFAULT_PROMPT = """
            You are the business agent of an employee of a manufacturing company. You do the work the employee gives \
            you, with the company's tools and only with them. Find and read what the work needs, do what it asks, \
            and when it is done answer the employee with the result they asked for. When a tool answers that a \
            request was refused or needs another check, take that answer as it is and go on with what you can do.""";

    private final AgentModels models;

    public BusinessAgent(AgentModels models) {
        this.models = models;
    }

    /**
     * @param toolNames the tools the work offers (the others of {@code tools} are not given to the agent)
     */
    public Transcript run(String model, String systemPrompt, String instruction, BusinessAgentTools tools,
                          Set<String> toolNames, Duration limit) {
        Instant started = Instant.now();
        ChatModel chatModel;
        try {
            chatModel = models.chatModel(model);
        } catch (RuntimeException e) {
            return new Transcript(model, systemPrompt, instruction, tools.calls(), null, "FAILED", e.getMessage(),
                    Map.of(), started, Instant.now());
        }
        ToolCallback[] callbacks = Arrays.stream(ToolCallbacks.from(tools))
                .filter(callback -> toolNames.contains(callback.getToolDefinition().name()))
                .toArray(ToolCallback[]::new);
        ExecutorService executor = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "business-agent");
            thread.setDaemon(true);
            return thread;
        });
        String answer = null;
        String stopReason;
        String failure = null;
        Map<String, Integer> usage = Map.of();
        try {
            // The model's tool step reads the live run's cap from this thread (docs/agent Agent중심-화면 AC-3).
            Future<ChatResponse> work = executor.submit(() -> {
                AgentRunCap.bind(tools.cap());
                try {
                    return ChatClient.create(chatModel).prompt().system(systemPrompt).user(instruction)
                            .toolCallbacks(callbacks).call().chatResponse();
                } finally {
                    AgentRunCap.bind(null);
                }
            });
            try {
                ChatResponse response = work.get(limit.toMillis(), TimeUnit.MILLISECONDS);
                answer = answerOf(response);
                usage = usage(response != null ? response.getMetadata().getUsage() : null);
                stopReason = tools.capReached() != null ? tools.capReached()
                        : tools.budgetUsed() ? "TOOL_BUDGET" : "ANSWERED";
            } catch (TimeoutException e) {
                tools.stop();
                work.cancel(true);
                stopReason = "TIME_LIMIT";
            } catch (ExecutionException e) {
                stopReason = "FAILED";
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                failure = cause.getClass().getSimpleName() + ": " + cause.getMessage();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            tools.stop();
            stopReason = "FAILED";
            failure = "Interrupted";
        } finally {
            executor.shutdownNow();
        }
        return new Transcript(model, systemPrompt, instruction, tools.calls(), answer, stopReason, failure, usage,
                started, Instant.now());
    }

    /**
     * The model's final answer: the text of everything it wrote in its last response. A response may carry the text and
     * the tool call as separate generations (Anthropic's does), so the first generation alone lost the explanation of a
     * business agent on Claude (docs/agent model comparison 2026-10-27). A response with one generation reads as it did.
     */
    static String answerOf(ChatResponse response) {
        if (response == null || response.getResult() == null) {
            return null;
        }
        String joined = response.getResults().stream()
                .map(generation -> generation.getOutput() == null ? null : generation.getOutput().getText())
                .filter(text -> text != null && !text.isBlank())
                .collect(Collectors.joining("\n"));
        return joined.isEmpty() ? response.getResult().getOutput().getText() : joined;
    }

    private static Map<String, Integer> usage(Usage usage) {
        return AgentUsage.counts(usage);
    }
}
