package io.contexa.contexacore.std.llm.client;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.ModelServerGateProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.gate.ModelCallTimer;
import io.contexa.contexacore.std.llm.gate.ModelServer;
import io.contexa.contexacore.std.llm.gate.ModelServerGates;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.retry.NonTransientAiException;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * O-1 in the orchestrator: every chat call passes the gate of its model server, the provider call limit counts from
 * the call's start, and a provider's rate limit or overload makes the server back off while the call waits in line
 * again instead of failing.
 */
class UnifiedLLMOrchestratorModelServerGateTest {

    private static final ModelServer LOCAL = ModelServer.of("ollama", "http://localhost:11434");

    @Test
    void chatCallsToOneServerRunNoMoreAtOnceThanItTakes() throws Exception {
        AtomicInteger running = new AtomicInteger();
        AtomicInteger mostAtOnce = new AtomicInteger();
        ChatModel model = answering(prompt -> {
            mostAtOnce.accumulateAndGet(running.incrementAndGet(), Math::max);
            sleep(100);
            running.decrementAndGet();
            return "ALLOW";
        });
        UnifiedLLMOrchestrator orchestrator = orchestrator(model, gates(2), new SecurityPlaneProperties());

        ExecutorService callers = Executors.newFixedThreadPool(6);
        try {
            List<Future<String>> calls = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                calls.add(callers.submit(() -> orchestrator.execute(ExecutionContext.from(new Prompt("decide")))
                        .block()));
            }
            for (Future<String> call : calls) {
                assertThat(call.get(10, TimeUnit.SECONDS)).isEqualTo("ALLOW");
            }
        } finally {
            callers.shutdownNow();
        }

        assertThat(mostAtOnce).hasValue(2);
    }

    @Test
    void theProviderCallLimitStartsWhenTheCallGetsIn() throws Exception {
        ChatModel model = answering(prompt -> {
            sleep(250);
            return "ALLOW";
        });
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getLlmTimeout().setProviderCallTimeoutMs(400L);
        UnifiedLLMOrchestrator orchestrator = orchestrator(model, gates(1), properties);

        ExecutorService callers = Executors.newFixedThreadPool(2);
        try {
            ExecutionContext first = ExecutionContext.from(new Prompt("decide"));
            ExecutionContext second = ExecutionContext.from(new Prompt("decide"));
            Future<String> one = callers.submit(() -> orchestrator.execute(first).block());
            Future<String> two = callers.submit(() -> orchestrator.execute(second).block());

            // Each waits up to 250 ms for the other and then calls for 250 ms: 500 ms from submit, 250 ms of call.
            assertThat(one.get(10, TimeUnit.SECONDS)).isEqualTo("ALLOW");
            assertThat(two.get(10, TimeUnit.SECONDS)).isEqualTo("ALLOW");
            long waited = Math.max(waitMs(first), waitMs(second));
            assertThat(waited).isGreaterThanOrEqualTo(150L);
            assertThat(first.getMetadata()).containsEntry("modelServer", LOCAL.key());
        } finally {
            callers.shutdownNow();
        }
    }

    @Test
    void theWaitAtTheGateIsLeftOutOfTheCallersTimer() {
        ChatModel model = answering(prompt -> "ALLOW");
        UnifiedLLMOrchestrator orchestrator = orchestrator(model, gates(1), new SecurityPlaneProperties());
        ModelCallTimer timer = ModelCallTimer.start(1_000L);
        ExecutionContext context = ExecutionContext.from(new Prompt("decide"));
        context.setModelCallTimer(timer);

        assertThat(orchestrator.execute(context).block()).isEqualTo("ALLOW");
        assertThat(context.getMetadata()).containsKey("modelServerWaitMs");
    }

    @Test
    void aRateLimitMakesTheServerBackOffAndTheCallWaitsInLineAgain() {
        AtomicInteger calls = new AtomicInteger();
        ChatModel model = answering(prompt -> {
            if (calls.getAndIncrement() < 2) {
                throw new NonTransientAiException("HTTP 429 - {\"type\":\"rate_limit_error\"}");
            }
            return "ALLOW";
        });
        UnifiedLLMOrchestrator orchestrator = orchestrator(model, gates(2), new SecurityPlaneProperties());
        ExecutionContext context = ExecutionContext.from(new Prompt("decide"));

        long started = System.nanoTime();
        assertThat(orchestrator.execute(context).block()).isEqualTo("ALLOW");

        assertThat(calls).hasValue(3);
        assertThat(context.getMetadata()).containsEntry("providerRetryCount", 2L);
        // Two back-offs of the gate (100 ms, then 200 ms) were waited in line.
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).isGreaterThanOrEqualTo(250L);
        assertThat(waitMs(context)).isGreaterThanOrEqualTo(150L);
    }

    private static long waitMs(ExecutionContext context) {
        Object value = context.getMetadata().get("modelServerWaitMs");
        return value instanceof Number number ? number.longValue() : 0L;
    }

    private static ModelServerGates gates(int maxConcurrent) {
        ModelServerGateProperties properties = new ModelServerGateProperties();
        properties.setSelfHostedMaxConcurrent(maxConcurrent);
        properties.setFirstBackOffMs(100L);
        return new ModelServerGates((model, kind) -> LOCAL, properties, 10_000L);
    }

    private static UnifiedLLMOrchestrator orchestrator(ChatModel model, ModelServerGates gates,
                                                       SecurityPlaneProperties properties) {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(selecting(model), null,
                new TieredLLMProperties(), new AdvisorRegistry(), properties);
        orchestrator.setModelServerGates(gates);
        return orchestrator;
    }

    private static ChatModel answering(Function<Prompt, String> answer) {
        return new ChatModel() {
            @Override
            public ChatResponse call(Prompt prompt) {
                return new ChatResponse(List.of(new Generation(new AssistantMessage(answer.apply(prompt)))));
            }

            @Override
            public ChatOptions getDefaultOptions() {
                return ChatOptions.builder().model("qwen3:8b").build();
            }
        };
    }

    private static ModelSelectionStrategy selecting(ChatModel model) {
        return new ModelSelectionStrategy() {
            @Override
            public ChatModel selectModel(ExecutionContext context) {
                return model;
            }

            @Override
            public Set<String> getSupportedModels() {
                return Set.of();
            }

            @Override
            public boolean isModelAvailable(String modelName) {
                return true;
            }
        };
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
