/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.llm.client;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.metadata.ChatGenerationMetadata;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T11 (design 4.5-E, BR-V3b): a Claude model that thinks more the longer its input is, and whose thinking counts against
 * the output limit. With thinking off nothing is cut; with the model's default thinking and no allowance the cuts grow
 * with the input and each call records them; an allowance keeps the answer's share. The fake model reads the thinking
 * field and the output limit of the options the orchestrator sends.
 */
class AnthropicThinkingGrowthTest {

    private static final int ANSWER_LIMIT = 2048;
    private static final List<Integer> INPUT_CHARS = List.of(2000, 6000, 10000, 14000);

    @Test
    void thinkingOffCutsNothingWhileTheDefaultThinkingCutsMoreAsTheInputGrows() {
        Map<Integer, String> off = run("OFF", 0);
        Map<Integer, String> modelDefault = run("PROVIDER_DEFAULT", 0);
        Map<Integer, String> withAllowance = run("PROVIDER_DEFAULT", 2048);

        assertThat(off.values()).as("thinking off").containsOnly("end_turn");
        assertThat(modelDefault).as("the model's default thinking, no allowance").isEqualTo(Map.of(
                2000, "end_turn", 6000, "end_turn", 10000, "max_tokens", 14000, "max_tokens"));
        assertThat(withAllowance.values()).as("an allowance of 2,048").containsOnly("end_turn");
    }

    @Test
    void everyCallRecordsWhatItSentAndHowTheProviderEnded() {
        GrowingThinkingModel model = new GrowingThinkingModel();
        ExecutionContext call = call(14000, "PROVIDER_DEFAULT", 0);

        execute(model, call);

        assertThat(call.getMetadata())
                .containsEntry("providerFinishReason", "max_tokens")
                .containsEntry("providerMaxTokensSent", ANSWER_LIMIT)
                .containsEntry("providerThinking", "ABSENT")
                .containsEntry("providerThinkingSource", "MODEL_DEFAULT");
    }

    private static Map<Integer, String> run(String mode, int allowance) {
        Map<Integer, String> finishReasons = new LinkedHashMap<>();
        for (int chars : INPUT_CHARS) {
            ExecutionContext call = call(chars, mode, allowance);
            execute(new GrowingThinkingModel(), call);
            finishReasons.put(chars, String.valueOf(call.getMetadata().get("providerFinishReason")));
        }
        return finishReasons;
    }

    private static void execute(ChatModel model, ExecutionContext call) {
        try {
            orchestrator(model).execute(call).block();
        } catch (RuntimeException expected) {
            // A call cut in its thinking has no answer; its finish reason is recorded before the failure.
        }
    }

    private static ExecutionContext call(int inputChars, String mode, int allowance) {
        ExecutionContext context = ExecutionContext.from(new Prompt(List.of(new UserMessage("x".repeat(inputChars)))));
        context.setMaxTokens(ANSWER_LIMIT);
        context.setTemperature(0.0d);
        context.addMetadata("anthropicThinking", mode);
        context.addMetadata("anthropicThinkingAllowanceTokens", allowance);
        context.addMetadata("disableRetries", true);
        return context;
    }

    private static UnifiedLLMOrchestrator orchestrator(ChatModel model) {
        ModelSelectionStrategy selection = new ModelSelectionStrategy() {
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
        return new UnifiedLLMOrchestrator(selection, null, new TieredLLMProperties(), new AdvisorRegistry(),
                new SecurityPlaneProperties());
    }

    /**
     * Claude Haiku 5.5 as the thinking documentation describes it: it thinks unless the request turns thinking off, a
     * token of thinking per four characters of input here, and the answer needs 300 tokens after the thinking.
     */
    private static final class GrowingThinkingModel implements ChatModel {

        private final AnthropicChatOptions defaults = AnthropicChatOptions.builder().model("claude-haiku-5-5")
                .maxTokens(500).build();

        @Override
        public ChatResponse call(Prompt prompt) {
            ChatOptions options = prompt.getOptions();
            int limit = options != null && options.getMaxTokens() != null ? options.getMaxTokens() : 500;
            boolean off = options instanceof AnthropicChatOptions anthropic && anthropic.getThinking() != null
                    && anthropic.getThinking().type() == AnthropicApi.ThinkingType.DISABLED;
            int inputChars = prompt.getInstructions().stream().mapToInt(message -> message.getText().length()).sum();
            int thinkingTokens = off ? 0 : inputChars / 4;
            int answerTokens = 300;
            List<Generation> generations = new ArrayList<>();
            if (thinkingTokens > 0) {
                generations.add(new Generation(AssistantMessage.builder().content("")
                        .properties(Map.of("signature", "thinking-signature")).build(),
                        ChatGenerationMetadata.builder().finishReason(
                                thinkingTokens >= limit ? "max_tokens" : "end_turn").build()));
            }
            if (thinkingTokens < limit) {
                boolean cut = thinkingTokens + answerTokens > limit;
                generations.add(new Generation(new AssistantMessage(cut ? "{\"action\":\"AL" : "{\"action\":\"ALLOW\"}"),
                        ChatGenerationMetadata.builder().finishReason(cut ? "max_tokens" : "end_turn").build()));
            }
            return new ChatResponse(generations);
        }

        @Override
        public ChatOptions getDefaultOptions() {
            return defaults;
        }
    }
}
