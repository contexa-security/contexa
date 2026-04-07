package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
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
    void executeShouldPreferRawExecutionForSecurityDecisionTargets() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
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

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(context.getMetadata("structuredOutputComplete", Boolean.class)).isFalse();
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

        @Override
        public Mono<String> execute(ExecutionContext context) {
            this.lastExecutionContext = context;
            this.rawExecutions++;
            return Mono.just("raw-response");
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
            return Mono.empty();
        }

        @Override
        public Mono<String> call(Prompt prompt) {
            return Mono.just("legacy-response");
        }

        @Override
        public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {
            this.entityExecutions++;
            return Mono.empty();
        }

        @Override
        public Flux<String> stream(Prompt prompt) {
            return Flux.just("legacy-stream-response");
        }
    }

    private static class TestContext extends DomainContext {
        @Override
        public String getDomainType() {
            return "test";
        }
    }
}
