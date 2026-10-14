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
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.metadata.ChatGenerationMetadata;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Claude Haiku 5.5 answers with its thinking first (Spring AI makes it the first generation, with its signature), and
 * Spring AI's entity conversion, output validation and streamed content read the first generation; next to the model
 * call the advisor leaves the thinking out, so they read the answer.
 */
class ThinkingGenerationAdvisorTest {

    record Verdict(String action) {
    }

    @Test
    void theEntityIsConvertedFromTheAnswerNotFromTheThinking() {
        ChatModel model = model(response(thinking("The user exports at night; check the approval."),
                answer("{\"action\":\"ALLOW\"}", "end_turn")));

        Verdict verdict = ChatClient.builder(model).defaultAdvisors(ThinkingGenerationAdvisor.INSTANCE).build()
                .prompt("decide").call().entity(Verdict.class);

        assertThat(verdict).isEqualTo(new Verdict("ALLOW"));
    }

    @Test
    void thinkingAloneLeavesAnEmptyAnswerWithItsFinishReason() {
        ChatModel model = model(response(thinking("The user exports at night; check")));

        ChatResponse response = ChatClient.builder(model).defaultAdvisors(ThinkingGenerationAdvisor.INSTANCE).build()
                .prompt("decide").call().chatResponse();

        assertThat(response.getResults()).hasSize(1);
        assertThat(response.getResult().getOutput().getText()).isEmpty();
        assertThat(response.getResult().getMetadata().getFinishReason()).isEqualTo("max_tokens");
    }

    @Test
    void streamedContentCarriesNoThinking() {
        ChatModel model = streamingModel(Flux.just(response(thinking("Checking the approval first.")),
                response(answer("{\"action\":", null)), response(answer("\"ALLOW\"}", "end_turn"))));

        List<String> parts = ChatClient.builder(model).defaultAdvisors(ThinkingGenerationAdvisor.INSTANCE).build()
                .prompt("decide").stream().content().collectList().block();

        assertThat(String.join("", parts)).isEqualTo("{\"action\":\"ALLOW\"}");
    }

    @Test
    void theOrchestratorConvertsAnEntityFromTheAnswer() {
        ChatModel model = model(response(thinking("Approval present."), answer("{\"action\":\"ALLOW\"}", "end_turn")));
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(selecting(model), null,
                new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());

        Verdict verdict = orchestrator.executeEntity(ExecutionContext.from(new Prompt("decide")), Verdict.class).block();

        assertThat(verdict).isEqualTo(new Verdict("ALLOW"));
    }

    private static Generation thinking(String text) {
        return new Generation(AssistantMessage.builder().content(text).properties(Map.of("signature", "sig")).build(),
                ChatGenerationMetadata.builder().finishReason("max_tokens").build());
    }

    private static Generation answer(String text, String finishReason) {
        return new Generation(new AssistantMessage(text),
                ChatGenerationMetadata.builder().finishReason(finishReason).build());
    }

    private static ChatResponse response(Generation... generations) {
        return new ChatResponse(List.of(generations));
    }

    private static ChatModel model(ChatResponse response) {
        return new ChatModel() {
            @Override
            public ChatResponse call(Prompt prompt) {
                return response;
            }
        };
    }

    private static ChatModel streamingModel(Flux<ChatResponse> chunks) {
        return new ChatModel() {
            @Override
            public ChatResponse call(Prompt prompt) {
                throw new UnsupportedOperationException("streamed only");
            }

            @Override
            public Flux<ChatResponse> stream(Prompt prompt) {
                return chunks;
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
}
