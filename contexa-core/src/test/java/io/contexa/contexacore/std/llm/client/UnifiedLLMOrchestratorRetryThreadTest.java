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
import org.springframework.ai.retry.TransientAiException;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A call that failed and may pass is sent again after its back-off, and the attempt after the back-off runs on the thread the
 * back-off ended on. Without a model server's gate the back-off is Reactor's {@code Retry.backoff}, which waits on the JVM's
 * {@code parallel} scheduler unless it is given another: the next attempt, a blocking call to the model, then ran on a thread of
 * that scheduler. It runs where the attempts after the gate's back-off run, on Contexa's blocking scheduler.
 */
class UnifiedLLMOrchestratorRetryThreadTest {

    @Test
    void theAttemptAfterABackOffRunsOnContexasBlockingThreadsAndTheCallStillPasses() {
        List<String> attempts = new CopyOnWriteArrayList<>();
        ChatModel model = new ChatModel() {
            @Override
            public ChatResponse call(Prompt prompt) {
                attempts.add(Thread.currentThread().getName());
                if (attempts.size() == 1) {
                    throw new TransientAiException("HTTP 500 - internal error");
                }
                return new ChatResponse(List.of(new Generation(new AssistantMessage("ALLOW"))));
            }

            @Override
            public ChatOptions getDefaultOptions() {
                return ChatOptions.builder().model("qwen3:8b").build();
            }
        };
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        // the call runs on the thread that subscribes, so the thread of each attempt is the model's
        properties.getLlmTimeout().setProviderCallTimeoutMs(0L);
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(selecting(model), null, new TieredLLMProperties(),
                new AdvisorRegistry(), properties);
        ExecutionContext context = ExecutionContext.from(new Prompt("decide"));

        String answer = orchestrator.execute(context).block(Duration.ofSeconds(30));

        // what the retry does is unchanged: one retry, the second attempt answers
        assertThat(answer).isEqualTo("ALLOW");
        assertThat(attempts).hasSize(2);
        assertThat(context.getMetadata()).containsEntry("providerRetryCount", 1L);
        assertThat(attempts.get(1)).startsWith("contexa-blocking-");
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
