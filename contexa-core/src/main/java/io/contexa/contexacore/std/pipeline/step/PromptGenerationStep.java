package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import reactor.core.publisher.Mono;

public class PromptGenerationStep implements PipelineStep {

    private final PromptEvidenceComposer promptEvidenceComposer;

    public PromptGenerationStep(PromptGenerator promptGenerator) {
        this.promptEvidenceComposer = new PromptEvidenceComposer(promptGenerator);
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(
            AIRequest<T> request,
            PipelineExecutionContext context) {

        return Mono.fromCallable(() -> promptEvidenceComposer.compose(request, context).promptResult());
    }

    @Override
    public PipelineConfiguration.PipelineStep getConfigStep() {
        return PipelineConfiguration.PipelineStep.PROMPT_GENERATION;
    }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null && promptEvidenceComposer.canCompose();
    }

    @Override
    public int getOrder() {
        return 3;
    }
}
