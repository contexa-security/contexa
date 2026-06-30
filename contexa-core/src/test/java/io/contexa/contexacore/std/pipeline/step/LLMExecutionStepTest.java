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

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.ObservedPromptTokenUsageRegistry;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LLMExecutionStepTest {

    @Test
    void executeShouldBuildExecutionContextWithCanonicalRuntimeSelectionOptions() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-runtime-selection");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));

        TestContext domainContext = new TestContext();
        domainContext.setUserId("user-1");
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("requestedModelId", "qwen3:8b");
        request.withParameter("temperature", 0.0d);
        request.withParameter("topP", 0.2d);
        request.withParameter("seed", 7);
        request.withParameter("maxTokens", 96);
        request.withParameter("openAiReasoningEffort", "minimal");
        request.withParameter("openAiVerbosity", "low");
        request.withParameter("disableRetries", true);
        request.withParameter("disableOllamaThinking", true);
        request.withParameter("decisionBoundaryMode", "RUNTIME_MODEL_SELECTION");

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(llmClient.lastExecutionContext).isNotNull();
        assertThat(llmClient.lastExecutionContext.getPreferredModel()).isEqualTo("qwen3:8b");
        assertThat(llmClient.lastExecutionContext.getTemperature()).isEqualTo(0.0d);
        assertThat(llmClient.lastExecutionContext.getTopP()).isEqualTo(0.2d);
        assertThat(llmClient.lastExecutionContext.getSeed()).isEqualTo(7);
        assertThat(llmClient.lastExecutionContext.getMaxTokens()).isEqualTo(96);
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry("requestedModelId", "qwen3:8b")
                .containsEntry("preferredModel", "qwen3:8b")
                .containsEntry("runtimeModelId", "qwen3:8b")
                .containsEntry("requestedModelSourceKey", "requestedModelId")
                .containsEntry("temperature", 0.0d)
                .containsEntry("topP", 0.2d)
                .containsEntry("seed", 7)
                .containsEntry("maxTokens", 96)
                .containsEntry("disableRetries", true)
                .containsEntry("disableOllamaThinking", true)
                .containsEntry("decisionBoundaryMode", "RUNTIME_MODEL_SELECTION");
        assertThat(context.getMetadata("requestedModelId", String.class)).isEqualTo("qwen3:8b");
        assertThat(context.getMetadata("temperature", Double.class)).isEqualTo(0.0d);
        assertThat(context.getMetadata("topP", Double.class)).isEqualTo(0.2d);
        assertThat(context.getMetadata("seed", Integer.class)).isEqualTo(7);
        assertThat(context.getMetadata("maxTokens", Integer.class)).isEqualTo(96);
        assertThat(context.getMetadata("disableRetries", Boolean.class)).isTrue();
        assertThat(context.getMetadata("disableOllamaThinking", Boolean.class)).isTrue();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
    }

    @Test
    void executeShouldSendPromptGenerationResultPromptObjectToLlmClientWithoutRebuildingIt() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-raw-identity-to-llm");
        String rawSystemPrompt = "RAW SYSTEM PROMPT";
        String rawUserPrompt = "=== CURRENT REQUEST AND EVENT ===\nTenantId: demo\nRequestPath: /admin/api/enterprise/verification/runtime/probe/normal/resource-001";
        Prompt finalPrompt = new Prompt(rawSystemPrompt + "\n" + rawUserPrompt);
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(
                        finalPrompt,
                        rawSystemPrompt,
                        rawUserPrompt,
                        rawSystemPrompt,
                        rawUserPrompt,
                        Map.of("promptTransformationMode", "IDENTITY", "promptRawTruthParity", true),
                        null));

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(llmClient.lastExecutionContext).isNotNull();
        assertThat(llmClient.lastExecutionContext.getPrompt()).isSameAs(finalPrompt);
        assertThat(llmClient.lastExecutionContext.getPrompt().getContents()).contains(rawSystemPrompt);
        assertThat(llmClient.lastExecutionContext.getPrompt().getContents()).contains(rawUserPrompt);
    }

    @Test
    void executeShouldUseRawGuardedExecutionForSecurityDecisionTargets() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Verified identity and scope support the request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-decision-raw");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        TestContext domainContext = new TestContext();
        domainContext.setUserId("user-1");
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("requestedModelId", "qwen3:8b");
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo(llmClient.rawResponse);
        assertThat(context.getMetadata("structuredOutputComplete", Boolean.class)).isFalse();
        assertThat(context.getMetadata("structuredOutputPolicy", String.class)).isEqualTo(StructuredOutputPolicy.RAW_FORBIDDEN.name());
        assertThat(context.getMetadata("structuredOutputMode", String.class)).isEqualTo("SECURITY_DECISION_RAW_GUARDED");
        assertThat(context.getMetadata("entityExecutionAttempted", Boolean.class)).isFalse();
        assertThat(context.getMetadata("entityExecutionSucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("rawExecutionAttempted", Boolean.class)).isTrue();
        assertThat(context.getMetadata("rawExecutionSucceeded", Boolean.class)).isTrue();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
        assertThat(llmClient.lastExecutionContext.getAdvisors()).isEmpty();
    }

    @Test
    void securityDecisionShouldIgnoreRuntimeModelAndOptionsUnlessOfficialVerificationPinned() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-runtime-override-blocked");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponse.class);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("responseType", SecurityDecisionResponse.class);
        request.withParameter("requestedModelId", "client-selected-model");
        request.withParameter("temperature", 0.0d);
        request.withParameter("topP", 0.2d);
        request.withParameter("seed", 7);
        request.withParameter("maxTokens", 96);
        request.withParameter("openAiReasoningEffort", "minimal");
        request.withParameter("openAiVerbosity", "low");
        request.withParameter("disableRetries", true);
        request.withParameter("disableOllamaThinking", true);
        request.withParameter("decisionBoundaryMode", "RUNTIME_MODEL_SELECTION");

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(llmClient.lastExecutionContext).isNotNull();
        assertThat(llmClient.lastExecutionContext.getPreferredModel()).isNull();
        assertThat(llmClient.lastExecutionContext.getTemperature()).isNull();
        assertThat(llmClient.lastExecutionContext.getTopP()).isNull();
        assertThat(llmClient.lastExecutionContext.getSeed()).isNull();
        assertThat(llmClient.lastExecutionContext.getMaxTokens()).isNull();
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry("openAiReasoningEffort", "minimal")
                .containsEntry("openAiVerbosity", "low");
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .doesNotContainKeys("requestedModelId", "preferredModel", "runtimeModelId", "temperature", "topP", "seed", "maxTokens");
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored.preferredModel", String.class)).isEqualTo("requestedModelId");
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored.temperature", String.class)).isEqualTo("temperature");
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored.decisionBoundaryMode", String.class)).isEqualTo("decisionBoundaryMode");
    }

    @Test
    void securityDecisionShouldAllowOfficialVerificationPinnedModelOnly() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-official-pinned-model");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("requestedModelId", "client-selected-model");
        request.withParameter("officialVerificationPinnedModelId", "gpt-5-nano");
        request.withParameter("temperature", 0.0d);

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(llmClient.lastExecutionContext).isNotNull();
        assertThat(llmClient.lastExecutionContext.getPreferredModel()).isEqualTo("gpt-5-nano");
        assertThat(llmClient.lastExecutionContext.getTemperature()).isNull();
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry("requestedModelId", "gpt-5-nano")
                .containsEntry("preferredModel", "gpt-5-nano")
                .containsEntry("runtimeModelId", "gpt-5-nano")
                .containsEntry("requestedModelSourceKey", "officialVerificationPinnedModelId")
                .doesNotContainKey("temperature");
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored.preferredModel", String.class)).isEqualTo("requestedModelId");
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored.temperature", String.class)).isEqualTo("temperature");
    }
    @Test
    void executeShouldDeriveActualPromptBudgetTelemetryFromProviderUsage() {
        ObservedPromptTokenUsageRegistry.clear();
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Verified runtime evidence remained consistent.\"}";
        llmClient.actualPromptTokens = 930;
        llmClient.actualCompletionTokens = 42;
        llmClient.actualTotalTokens = 972;
        llmClient.actualTokenUsageAvailable = true;

        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-actual-token-usage");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        context.addMetadata("budgetMaxInputTokens", 1500);
        context.addMetadata("llmTotalPromptLength", 1860);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("officialVerificationPinnedModelId", "gpt-4o-mini");
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        try {
            Object response = step.execute(request, context).block();

            assertThat(response).isEqualTo(llmClient.rawResponse);
            assertThat(context.getMetadata("actualPromptTokens", Number.class)).isEqualTo(930);
            assertThat(context.getMetadata("actualPromptBudgetRemainingTokens", Number.class)).isEqualTo(570);
            assertThat(context.getMetadata("actualPromptBudgetExceeded", Boolean.class)).isFalse();
            assertThat(context.getMetadata("actualPromptUsageSource", String.class)).isEqualTo("PROVIDER_USAGE");
            assertThat(context.getMetadata("actualPromptBudgetUtilizationRate", Double.class)).isEqualTo(0.62d);
            assertThat(ObservedPromptTokenUsageRegistry.hasCalibration("gpt-4o-mini")).isTrue();
        } finally {
            ObservedPromptTokenUsageRegistry.clear();
        }
    }

    @Test
    void executeShouldBypassSecurityDecisionEntityFailureWithRawGuardedExecution() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.entityError = new IllegalStateException("schema mismatch");
        llmClient.rawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Additional verification is required.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-decision-failure");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("requestedModelId", "qwen3:8b");
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo(llmClient.rawResponse);
        assertThat(context.getMetadata("entityExecutionSucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("rawExecutionAttempted", Boolean.class)).isTrue();
        assertThat(context.getMetadata("rawExecutionSucceeded", Boolean.class)).isTrue();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
    }

    @Test
    void executeShouldReturnEmptyRawResultForSecurityDecisionRawExecutionFailure() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawError = new IllegalStateException("connection refused");
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-decision-raw-failure");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("");
        assertThat(context.getMetadata("rawExecutionSucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("MODEL_UNAVAILABLE");
        assertThat(context.getMetadata("securityDecisionFallbackReason", String.class)).isEqualTo("LLM_EXECUTION_FAILED");
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
    }

    @Test
    void executeShouldUseValidatedConverterWhenNativeStructuredOutputIsDisabled() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("ALLOW");
        lite.setConfidence(0.77d);
        lite.setRiskScore(0.14d);
        lite.setReasoning("Validated converter path preserved the structured security decision.");
        lite.setMitre("UNKNOWN");
        llmClient.entityResponse = lite;
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-native-disabled");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("officialVerificationPinnedModelId", "gpt-4o-mini");
        request.withParameter("nativeStructuredOutputEnabled", false);
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(context.getMetadata("structuredOutputMode", String.class))
                .isEqualTo("SECURITY_DECISION_RAW_GUARDED");
        assertThat(llmClient.lastExecutionContext.getAdvisors()).isEmpty();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
    }

    @Test
    void executeShouldResolveRuntimeModelIdAliasFromContextMetadata() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-runtime-model-id-alias");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("runtimeModelId", "qwen2.5:7b");

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(llmClient.lastExecutionContext).isNotNull();
        assertThat(llmClient.lastExecutionContext.getPreferredModel()).isEqualTo("qwen2.5:7b");
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry("requestedModelId", "qwen2.5:7b")
                .containsEntry("runtimeModelId", "qwen2.5:7b")
                .containsEntry("requestedModelSourceKey", "runtimeModelId");
    }

    private static class RecordingLlmClient implements LLMClient, LLMOperations {

        private ExecutionContext lastExecutionContext;
        private int rawExecutions;
        private int entityExecutions;
        private String rawResponse = "raw-response";
        private Throwable rawError;
        private SecurityDecisionResponseLite entityResponse;
        private Throwable entityError;
        private Integer actualPromptTokens;
        private Integer actualCompletionTokens;
        private Integer actualTotalTokens;
        private Boolean actualTokenUsageAvailable;

        @Override
        public Mono<String> execute(ExecutionContext context) {
            this.lastExecutionContext = context;
            this.rawExecutions++;
            applyUsageMetadata(context);
            if (rawError != null) {
                return Mono.error(rawError);
            }
            return Mono.just(rawResponse);
        }

        @Override
        public Flux<String> stream(ExecutionContext context) {
            this.lastExecutionContext = context;
            return Flux.just("stream-response");
        }

        @Override
        public <T> Mono<T> executeEntity(ExecutionContext context, Class<T> targetType) {
            this.lastExecutionContext = context;
            this.entityExecutions++;
            applyUsageMetadata(context);
            if (entityError != null) {
                return Mono.error(entityError);
            }
            return Mono.just(targetType.cast(entityResponse));
        }

        @Override
        public Mono<String> call(Prompt prompt) {
            return Mono.just("legacy-response");
        }

        @Override
        public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {
            this.entityExecutions++;
            if (entityError != null) {
                return Mono.error(entityError);
            }
            return Mono.just(targetType.cast(entityResponse));
        }

        @Override
        public Flux<String> stream(Prompt prompt) {
            return Flux.just("legacy-stream-response");
        }

        private void applyUsageMetadata(ExecutionContext context) {
            if (context == null) {
                return;
            }
            if (actualPromptTokens != null) {
                context.addMetadata("actualPromptTokens", actualPromptTokens);
            }
            if (actualCompletionTokens != null) {
                context.addMetadata("actualCompletionTokens", actualCompletionTokens);
            }
            if (actualTotalTokens != null) {
                context.addMetadata("actualTotalTokens", actualTotalTokens);
            }
            if (actualTokenUsageAvailable != null) {
                context.addMetadata("actualTokenUsageAvailable", actualTokenUsageAvailable);
            }
        }
    }

    private static class TestContext extends DomainContext {
        @Override
        public String getDomainType() {
            return "test";
        }
    }
}
