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
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.tool.annotation.Tool;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A tool call that returns the whole response runs on the same path as any other call: the tools reach the model, and
 * a failure that may pass when sent again (a reset connection) is sent again.
 */
class UnifiedLLMOrchestratorToolCallTest {

    static class ApprovalTools {

        @Tool(description = "Looks up the approval of a project transfer")
        String lookupApproval(String project) {
            return "approved";
        }
    }

    @Test
    void aToolCallResponseCarriesTheToolsAndIsSentAgainAfterAResetConnection() {
        AtomicInteger calls = new AtomicInteger();
        AtomicReference<Prompt> sent = new AtomicReference<>();
        ChatModel model = new ChatModel() {
            @Override
            public ChatResponse call(Prompt prompt) {
                sent.set(prompt);
                if (calls.getAndIncrement() == 0) {
                    throw new UncheckedIOException(new IOException("connection reset"));
                }
                return new ChatResponse(List.of(new Generation(new AssistantMessage("approved"))));
            }

            @Override
            public ChatOptions getDefaultOptions() {
                return ToolCallingChatOptions.builder().build();
            }
        };
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(selecting(model), null,
                new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());

        ChatResponse response = orchestrator.callToolsResponse(new Prompt("Is the transfer of GB-500 approved?"),
                List.of(new ApprovalTools())).block();

        assertThat(response.getResult().getOutput().getText()).isEqualTo("approved");
        assertThat(calls).hasValue(2);
        assertThat(((ToolCallingChatOptions) sent.get().getOptions()).getToolCallbacks())
                .extracting(callback -> callback.getToolDefinition().name()).contains("lookupApproval");
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
