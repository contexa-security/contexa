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
package io.contexa.contexacore.std.llm.handler;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The streaming path: the tools a caller streams with reach the model, and on the first tier only a timeout becomes
 * the timeout answer (a refused request stays an error the caller sees).
 */
class StreamingToolsAndErrorsTest {

    static class ApprovalTools {

        @Tool(description = "Looks up the approval of a project transfer")
        String lookupApproval(String project) {
            return "approved";
        }
    }

    @Test
    void theToolsAStreamIsAskedWithReachTheModel() {
        AtomicReference<Prompt> sent = new AtomicReference<>();
        ChatModel model = new ChatModel() {
            @Override
            public ChatResponse call(Prompt prompt) {
                throw new UnsupportedOperationException("streamed only");
            }

            @Override
            public Flux<ChatResponse> stream(Prompt prompt) {
                sent.set(prompt);
                return Flux.just(new ChatResponse(List.of(new Generation(new AssistantMessage("approved")))));
            }

            @Override
            public ChatOptions getDefaultOptions() {
                return ToolCallingChatOptions.builder().build();
            }
        };
        TieredLLMProperties properties = new TieredLLMProperties();
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(selecting(model),
                new DefaultStreamingHandler(properties, new JsonStreamingProcessor()), properties,
                new AdvisorRegistry(), new SecurityPlaneProperties());

        orchestrator.streamTools(new Prompt("Is the transfer of GB-500 approved?"), List.of(new ApprovalTools()))
                .collectList().block();

        assertThat(sent.get()).isNotNull();
        assertThat(sent.get().getOptions()).isInstanceOf(ToolCallingChatOptions.class);
        assertThat(((ToolCallingChatOptions) sent.get().getOptions()).getToolCallbacks())
                .extracting(callback -> callback.getToolDefinition().name()).contains("lookupApproval");
    }

    @Test
    void onTheFirstTierARefusedRequestStaysAnError() {
        DefaultStreamingHandler handler = new DefaultStreamingHandler(new TieredLLMProperties(), new JsonStreamingProcessor());

        Flux<String> refused = ReflectionTestUtils.invokeMethod(handler, "optimizeForTier",
                Flux.<String>error(new IllegalStateException("HTTP 400 - invalid_request_error")), 1);

        assertThatThrownBy(() -> refused.collectList().block()).hasMessageContaining("HTTP 400");
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
}
