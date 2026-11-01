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
package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.metadata.ChatGenerationMetadata;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * QF-50: a chat model behind the orchestrator a decision runs on in production. It answers each call with the next
 * scripted response and keeps the output limit and the message count each call carried; a call past the script fails.
 * A thinking-only response has the shape Spring AI's Anthropic model gives when the output limit stops the model in its
 * thinking: one thinking generation (its signature) that ends at the limit, and no answer.
 */
public final class ScriptedChatModel implements ChatModel {

    private final List<ChatResponse> responses;
    private final ChatOptions defaultOptions;
    private final List<Integer> maxTokens = Collections.synchronizedList(new ArrayList<>());
    private final List<Integer> messageCounts = Collections.synchronizedList(new ArrayList<>());
    private final List<String> thinking = Collections.synchronizedList(new ArrayList<>());

    public ScriptedChatModel(ChatResponse... responses) {
        this(null, responses);
    }

    private ScriptedChatModel(ChatOptions defaultOptions, ChatResponse... responses) {
        this.defaultOptions = defaultOptions;
        this.responses = List.of(responses);
    }

    /** The script answered as a Claude model: its default options name the model, as Spring AI's Anthropic ones do. */
    public static ScriptedChatModel claude(String modelId, ChatResponse... responses) {
        return new ScriptedChatModel(AnthropicChatOptions.builder().model(modelId).maxTokens(500).build(), responses);
    }

    @Override
    public ChatOptions getDefaultOptions() {
        return defaultOptions != null ? defaultOptions : ChatOptions.builder().build();
    }

    /** An answer with its text and the finish reason the provider gave it. */
    public static ChatResponse answer(String text, String finishReason) {
        return new ChatResponse(List.of(new Generation(new AssistantMessage(text),
                ChatGenerationMetadata.builder().finishReason(finishReason).build())));
    }

    /** Thinking alone, ended with the given finish reason before any answer. */
    public static ChatResponse thinkingOnly(String finishReason) {
        return new ChatResponse(List.of(new Generation(AssistantMessage.builder()
                .content("The request reads a project at night, so every fact is weighed before the answer.")
                .properties(Map.of("signature", "thinking-signature")).build(),
                ChatGenerationMetadata.builder().finishReason(finishReason).build())));
    }

    /** The orchestrator, selecting this model for every call. */
    public UnifiedLLMOrchestrator orchestrator() {
        ChatModel model = this;
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

    @Override
    public ChatResponse call(Prompt prompt) {
        int call;
        synchronized (maxTokens) {
            call = maxTokens.size();
            maxTokens.add(prompt.getOptions() != null ? prompt.getOptions().getMaxTokens() : null);
            messageCounts.add(prompt.getInstructions().size());
            thinking.add(prompt.getOptions() instanceof AnthropicChatOptions anthropic && anthropic.getThinking() != null
                    ? anthropic.getThinking().type().name() : null);
        }
        if (call >= responses.size()) {
            throw new IllegalStateException("No scripted response for model call " + (call + 1));
        }
        return responses.get(call);
    }

    /** The output limit of each call, in the order of the calls. */
    public List<Integer> maxTokens() {
        synchronized (maxTokens) {
            return new ArrayList<>(maxTokens);
        }
    }

    /** The thinking type each call carried (ENABLED, DISABLED), null for none, in the order of the calls. */
    public List<String> thinking() {
        synchronized (maxTokens) {
            return new ArrayList<>(thinking);
        }
    }

    /** The number of messages each call carried, in the order of the calls. */
    public List<Integer> messageCounts() {
        synchronized (maxTokens) {
            return new ArrayList<>(messageCounts);
        }
    }
}
