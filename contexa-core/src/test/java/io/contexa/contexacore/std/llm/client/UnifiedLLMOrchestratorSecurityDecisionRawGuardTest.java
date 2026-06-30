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

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

class UnifiedLLMOrchestratorSecurityDecisionRawGuardTest {

    @Test
    void executeEntityShouldUseRawGuardedParserForSecurityDecisionLite() {
        UnifiedLLMOrchestrator orchestrator = orchestratorReturning("""
                {
                  "action": "ALLOW",
                  "confidence": 0.9,
                  "mitre": "",
                  "reasoning": "The request has a known user and read-only scope.",
                  "riskScore":
                """);
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setRequestId("security-raw-1");

        SecurityDecisionResponseLite result = orchestrator
                .executeEntity(context, SecurityDecisionResponseLite.class)
                .block();

        assertThat(result).isNotNull();
        assertThat(result.getAction()).isEqualTo("ALLOW");
        assertThat(result.getReasoning()).isEqualTo("The request has a known user and read-only scope.");
        assertThat(result.getRiskScore()).isEqualTo(0.20d);
        assertThat(context.getMetadata())
                .containsEntry("entityExecutionAttempted", false)
                .containsEntry("entityExecutionSucceeded", false)
                .containsEntry("rawExecutionAttempted", true)
                .containsEntry("rawExecutionSucceeded", true)
                .containsEntry("structuredOutputMode", "SECURITY_DECISION_RAW_GUARDED")
                .containsEntry("securityDecisionParsingMode", "RAW_GUARDED")
                .containsEntry("securityDecisionParseFailureCategory", "TRUNCATED_JSON");
    }

    @Test
    void executeEntityShouldFailClosedWithProviderTimeoutCategory() {
        UnifiedLLMOrchestrator orchestrator = orchestratorFailing(new RuntimeException(new TimeoutException("provider timeout")));
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setRequestId("security-raw-timeout");

        SecurityDecisionResponseLite result = orchestrator
                .executeEntity(context, SecurityDecisionResponseLite.class)
                .block();

        assertThat(result).isNotNull();
        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(context.getMetadata())
                .containsEntry("rawExecutionSucceeded", false)
                .containsEntry("securityDecisionParseFailureCategory", "PROVIDER_CALL_TIMEOUT")
                .containsEntry("securityDecisionFallbackAction", "CHALLENGE")
                .containsEntry("securityDecisionFallbackReason", "LLM_EXECUTION_FAILED");
    }
    @Test
    void executeEntityShouldFailClosedWhenSecurityDecisionRawExecutionFails() {
        UnifiedLLMOrchestrator orchestrator = orchestratorFailing(new IllegalStateException("connection refused"));
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setRequestId("security-raw-2");

        SecurityDecisionResponseLite result = orchestrator
                .executeEntity(context, SecurityDecisionResponseLite.class)
                .block();

        assertThat(result).isNotNull();
        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(result.getReasoning()).isEqualTo("Model output was incomplete; challenge is required.");
        assertThat(context.getMetadata())
                .containsEntry("rawExecutionSucceeded", false)
                .containsEntry("securityDecisionParseFailureCategory", "MODEL_UNAVAILABLE")
                .containsEntry("securityDecisionFallbackAction", "CHALLENGE")
                .containsEntry("securityDecisionFallbackReason", "LLM_EXECUTION_FAILED");
    }

    private UnifiedLLMOrchestrator orchestratorReturning(String rawResponse) {
        return new UnifiedLLMOrchestrator(noModelSelection(), noStreaming(), new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties()) {
            @Override
            public Mono<String> execute(ExecutionContext context) {
                return Mono.just(rawResponse);
            }
        };
    }

    private UnifiedLLMOrchestrator orchestratorFailing(RuntimeException error) {
        return new UnifiedLLMOrchestrator(noModelSelection(), noStreaming(), new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties()) {
            @Override
            public Mono<String> execute(ExecutionContext context) {
                return Mono.error(error);
            }
        };
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
            public Flux<String> handleStreamingWithTools(ChatClient chatClient, ExecutionContext context, ChatModel selectedModel) {
                return Flux.empty();
            }
        };
    }
}
