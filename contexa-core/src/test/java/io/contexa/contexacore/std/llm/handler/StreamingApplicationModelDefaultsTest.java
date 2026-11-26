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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.annotation.Tool;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-9: a stream Contexa runs on a chat model it was handed as the application has it, with and without tools, leaves the
 * model's default options as the application set them (a Claude model that takes only the default sampling, whose
 * defaults hold Spring AI's temperature and a top-k).
 */
@DisplayName("Contexa 스트리밍 호출은 앱 채팅 모델의 기본 옵션을 바꾸지 않는다")
class StreamingApplicationModelDefaultsTest {

    static class ApprovalTools {

        @Tool(description = "Looks up the approval of a project transfer")
        String lookupApproval(String project) {
            return "approved";
        }
    }

    @Test
    @DisplayName("도구 없는 스트림과 도구 스트림 뒤에도 앱 모델의 기본 옵션은 그대로다")
    void aStreamKeepsTheApplicationsDefaultOptions() {
        ApplicationsStreamingModel model = new ApplicationsStreamingModel();
        TieredLLMProperties properties = new TieredLLMProperties();
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(selecting(model),
                new DefaultStreamingHandler(properties, new JsonStreamingProcessor()), properties,
                new AdvisorRegistry(), new SecurityPlaneProperties());

        orchestrator.stream(new Prompt("Is the transfer of GB-500 approved?")).collectList().block();
        orchestrator.streamTools(new Prompt("Is the transfer of GB-500 approved?"), List.of(new ApprovalTools()))
                .collectList().block();

        assertThat(model.streamed).isEqualTo(2);
        assertThat(model.defaultOptions.getTemperature()).isEqualTo(0.8d);
        assertThat(model.defaultOptions.getTopK()).isEqualTo(5);
        assertThat(model.defaultOptions.getMaxTokens()).isEqualTo(500);
    }

    /** An application's chat model that keeps its defaults in a field, as Spring AI's provider models do. */
    private static final class ApplicationsStreamingModel implements ChatModel {

        private final AnthropicChatOptions defaultOptions = AnthropicChatOptions.builder().model("claude-haiku-5-5")
                .temperature(0.8d).topK(5).maxTokens(500).build();
        private int streamed;

        @Override
        public ChatResponse call(Prompt prompt) {
            throw new UnsupportedOperationException("streamed only");
        }

        @Override
        public Flux<ChatResponse> stream(Prompt prompt) {
            streamed++;
            return Flux.just(new ChatResponse(List.of(new Generation(new AssistantMessage("approved")))));
        }

        @Override
        public ChatOptions getDefaultOptions() {
            return defaultOptions.copy();
        }
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
