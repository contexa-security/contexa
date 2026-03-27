package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
public class PromptGenerationStep implements PipelineStep {

    private final PromptGenerator promptGenerator;

    public PromptGenerationStep(
            PromptGenerator promptGenerator) {
        this.promptGenerator = promptGenerator;
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(
            AIRequest<T> request,
            PipelineExecutionContext context) {

        return Mono.fromCallable(() -> {

            ContextRetriever.ContextRetrievalResult contextResult =
                    context.getStepResult(
                            PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL,
                            ContextRetriever.ContextRetrievalResult.class
                    );

            String systemMetadata = context.getStepResult(
                    PipelineConfiguration.PipelineStep.PREPROCESSING,
                    String.class
            );

            String contextInfo = contextResult != null ? contextResult.getContextInfo() : "";
            String metadata = systemMetadata != null ? systemMetadata : "";
            PromptGenerationResult promptResult = promptGenerator.generatePrompt(request, contextInfo, metadata);

            Class<?> aiGenerationType = promptGenerator.getAIGenerationType(request);
            if (aiGenerationType != null) {
                context.addMetadata("aiGenerationType", aiGenerationType);
            }
            if (promptResult.getPromptExecutionMetadata() != null) {
                context.addMetadata("promptExecutionMetadata", promptResult.getPromptExecutionMetadata());
                context.addMetadata("promptHash", promptResult.getPromptExecutionMetadata().promptHash());
                context.addMetadata("promptVersion", promptResult.getPromptExecutionMetadata()
                        .governanceDescriptor()
                        .promptVersion());
                context.addMetadata("budgetProfile", promptResult.getPromptExecutionMetadata().budgetProfile().profileKey());
                context.addMetadata("promptEvidenceCompleteness", promptResult.getPromptExecutionMetadata().promptEvidenceCompleteness().name());
                context.addMetadata("omittedSections", promptResult.getPromptExecutionMetadata().omittedSections());
            }
            context.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION, promptResult);

            return promptResult;
        });
    }

    @Override
    public PipelineConfiguration.PipelineStep getConfigStep() {
        return PipelineConfiguration.PipelineStep.PROMPT_GENERATION;
    }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null && promptGenerator != null;
    }

    @Override
    public int getOrder() {
        return 3;
    }

}
