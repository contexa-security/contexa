package io.contexa.contexacore.std.llm.client;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.metadata.ChatGenerationMetadata;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.metadata.ChatResponseMetadata;
import org.springframework.ai.chat.metadata.DefaultUsage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** What the orchestrator records from a provider response. */
class UnifiedLLMOrchestratorResponseMetadataTest {

    /**
     * P3-EXTRA-8: a provider that reports no cached token count leaves the cache hit unknown, so the orchestrator records
     * no hit value instead of a miss.
     */
    @Test
    void aProviderThatReportsNoCachedTokensLeavesTheCacheHitUnknown() {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(noModelSelection(), noStreaming(),
                new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.addMetadata("promptCacheEligible", true);
        ChatResponse response = new ChatResponse(List.of(new Generation(new AssistantMessage("{}"))),
                ChatResponseMetadata.builder().usage(new DefaultUsage(100, 10)).build());

        ReflectionTestUtils.invokeMethod(orchestrator, "captureResponseMetadata", context, null, response);

        assertThat(context.getMetadata())
                .containsEntry("actualPromptTokens", 100)
                .doesNotContainKey("cachedPromptTokens")
                .doesNotContainKey("promptCacheHit");
    }

    /**
     * A provider that returns its thinking as generations before the answer (Anthropic's thinking blocks, with their
     * signature, or redacted with their data) gives the answer as the text of its other generations.
     */
    @Test
    void theThinkingGenerationsBeforeTheAnswerAreNotTheAnswer() {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(noModelSelection(), noStreaming(),
                new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());
        ChatResponse response = new ChatResponse(List.of(
                new Generation(AssistantMessage.builder().content("The export is at night, so the user is checked.")
                        .properties(Map.of("signature", "thinking-signature")).build()),
                new Generation(AssistantMessage.builder().properties(Map.of("data", "redacted-thinking")).build()),
                new Generation(new AssistantMessage("{\"action\":\"ALLOW\"}"))));

        String answer = ReflectionTestUtils.invokeMethod(orchestrator, "extractResponseText", response);

        assertThat(answer).isEqualTo("{\"action\":\"ALLOW\"}");
    }

    /** Claude Haiku 5.5: when the output limit stops it after its thinking, no answer came back. */
    @Test
    void thinkingAloneIsNoAnswer() {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(noModelSelection(), noStreaming(),
                new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());
        ChatResponse response = new ChatResponse(List.of(new Generation(AssistantMessage.builder()
                .content("The export is at night.").properties(Map.of("signature", "thinking-signature")).build())));

        String answer = ReflectionTestUtils.invokeMethod(orchestrator, "extractResponseText", response);

        assertThat(answer).isNull();
    }

    /**
     * Claude Haiku 5.5: Anthropic counts its prompt cache reads and writes apart from its input tokens, so the prompt
     * tokens are all three (as OpenAI counts them), the cache reads are the cached tokens and the writes are kept.
     */
    @Test
    void anAnthropicUsageCountsEveryInputTokenAndItsCacheReads() {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(noModelSelection(), noStreaming(),
                new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        AnthropicApi.Usage anthropic = new AnthropicApi.Usage(3329, 838, 12, 4372);
        ChatResponse response = new ChatResponse(List.of(new Generation(new AssistantMessage("{}"))),
                ChatResponseMetadata.builder().usage(new DefaultUsage(3329, 838, 4167, anthropic)).build());

        ReflectionTestUtils.invokeMethod(orchestrator, "captureResponseMetadata", context, null, response);

        assertThat(context.getMetadata())
                .containsEntry("actualPromptTokens", 7713)
                .containsEntry("actualCompletionTokens", 838)
                .containsEntry("actualTotalTokens", 8551)
                .containsEntry("cachedPromptTokens", 4372)
                .containsEntry("cacheWritePromptTokens", 12)
                .containsEntry("promptCacheHit", true);
    }

    /**
     * The finish reason of the answer is kept (a cut at the output limit or a refusal is told apart later), and the
     * reasoning tokens OpenAI reports inside its output tokens.
     */
    @Test
    void theFinishReasonOfTheAnswerAndTheReasoningTokensAreRecorded() {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(noModelSelection(), noStreaming(),
                new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());
        ExecutionContext anthropic = ExecutionContext.from(new Prompt("security prompt"));
        ChatResponse thought = new ChatResponse(List.of(
                new Generation(AssistantMessage.builder().content("").properties(Map.of("signature", "s")).build(),
                        ChatGenerationMetadata.builder().finishReason("end_turn").build()),
                new Generation(new AssistantMessage("{}"), ChatGenerationMetadata.builder().finishReason("end_turn").build())),
                ChatResponseMetadata.builder().usage(new DefaultUsage(3329, 838)).build());
        ReflectionTestUtils.invokeMethod(orchestrator, "captureResponseMetadata", anthropic, null, thought);
        assertThat(anthropic.getMetadata()).containsEntry("providerFinishReason", "end_turn");

        ExecutionContext openAi = ExecutionContext.from(new Prompt("security prompt"));
        OpenAiApi.Usage usage = new OpenAiApi.Usage(212, 4337, 4549, null,
                new OpenAiApi.Usage.CompletionTokenDetails(157, null, null, null));
        ChatResponse reasoned = new ChatResponse(List.of(new Generation(new AssistantMessage("{}"),
                ChatGenerationMetadata.builder().finishReason("STOP").build())),
                ChatResponseMetadata.builder().usage(new DefaultUsage(4337, 212, 4549, usage)).build());
        ReflectionTestUtils.invokeMethod(orchestrator, "captureResponseMetadata", openAi, null, reasoned);
        assertThat(openAi.getMetadata()).containsEntry("providerFinishReason", "STOP").containsEntry("reasoningTokens", 157);
    }

    /** A number the response metadata keeps under another name (a creation time, an evaluation count) is no cache count. */
    @Test
    void aNumberUnderAnotherNameIsNoCachedTokenCount() {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(noModelSelection(), noStreaming(),
                new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        ChatResponse response = new ChatResponse(List.of(new Generation(new AssistantMessage("{}"))),
                ChatResponseMetadata.builder().usage(new DefaultUsage(100, 10))
                        .keyValue("created", 1760000000L).keyValue("eval-count", 10).build());

        ReflectionTestUtils.invokeMethod(orchestrator, "captureResponseMetadata", context, null, response);

        assertThat(context.getMetadata()).doesNotContainKey("cachedPromptTokens").doesNotContainKey("promptCacheHit");
    }

    @Test
    void aSingleGenerationIsTheAnswerAsItIs() {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(noModelSelection(), noStreaming(),
                new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());
        ChatResponse response = new ChatResponse(List.of(new Generation(new AssistantMessage("{\"action\":\"BLOCK\"}"))));

        String answer = ReflectionTestUtils.invokeMethod(orchestrator, "extractResponseText", response);

        assertThat(answer).isEqualTo("{\"action\":\"BLOCK\"}");
    }

    private ModelSelectionStrategy noModelSelection() {
        return new ModelSelectionStrategy() {
            @Override
            public ChatModel selectModel(ExecutionContext context) {
                return null;
            }

            @Override
            public Set<String> getSupportedModels() {
                return Set.of();
            }

            @Override
            public boolean isModelAvailable(String modelName) {
                return false;
            }
        };
    }

    private StreamingHandler noStreaming() {
        return new StreamingHandler() {
            @Override
            public Flux<String> handleStreaming(ChatClient chatClient, ExecutionContext context, ChatModel selectedModel) {
                return Flux.empty();
            }

            @Override
            public Flux<String> handleStreamingWithTools(ChatClient chatClient, ExecutionContext context,
                                                         ChatModel selectedModel) {
                return Flux.empty();
            }
        };
    }
}
