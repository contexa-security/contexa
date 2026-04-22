package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.ContextRetrievalStep;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import io.contexa.contexacore.std.pipeline.step.PipelineStep;
import io.contexa.contexacore.std.pipeline.step.PostprocessingStep;
import io.contexa.contexacore.std.pipeline.step.PreprocessingStep;
import io.contexa.contexacore.std.pipeline.step.PromptGenerationStep;
import io.contexa.contexacore.std.pipeline.step.ResponseParsingStep;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class UniversalPipelineExecutorTest {

    @Test
    void executeShouldSkipConfiguredStepWhenStepCannotExecute() {
        CountingStep step = new CountingStep(PipelineConfiguration.PipelineStep.PREPROCESSING, false);
        UniversalPipelineExecutor executor = new TestPipelineExecutor(step);
        AIRequest<TestContext> request = new AIRequest<>(
                new TestContext(),
                new TemplateType("standard"),
                new DiagnosisType("general"));

        executor.executeStepsWithConfig(
                        request,
                        PipelineConfiguration.builder()
                                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                                .build(),
                        new PipelineExecutionContext("test"),
                        List.of(step),
                        false,
                        "TEST")
                .block();

        assertThat(step.executions.get()).isZero();
    }

    private static final class TestPipelineExecutor extends UniversalPipelineExecutor {
        private TestPipelineExecutor(PipelineStep step) {
            super(
                    new ContextRetrievalStep(null),
                    new PreprocessingStep(),
                    new PromptGenerationStep(null),
                    new LLMExecutionStep(null),
                    null,
                    new ResponseParsingStep(),
                    new PostprocessingStep(Optional.empty()));
        }
    }

    private static final class CountingStep implements PipelineStep {
        private final PipelineConfiguration.PipelineStep configStep;
        private final boolean canExecute;
        private final AtomicInteger executions = new AtomicInteger();

        private CountingStep(PipelineConfiguration.PipelineStep configStep, boolean canExecute) {
            this.configStep = configStep;
            this.canExecute = canExecute;
        }

        @Override
        public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
            executions.incrementAndGet();
            return Mono.empty();
        }

        @Override
        public PipelineConfiguration.PipelineStep getConfigStep() {
            return configStep;
        }

        @Override
        public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
            return canExecute;
        }
    }

    private static final class TestContext extends DomainContext {
        @Override
        public String getDomainType() {
            return "test";
        }
    }
}
