package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.PipelineStep;
import io.contexa.contexacore.std.pipeline.step.PostprocessingStep;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import reactor.core.publisher.Mono;

public class PostprocessingStepExecutionHandler implements StepExecutionHandler {
    @Override
    public boolean canHandle(PipelineStep step) {
        return step instanceof PostprocessingStep;
    }

    @Override
    public <T extends DomainContext, R extends AIResponse> Mono<PipelineExecutionContext> execute(
            PipelineStep step, AIRequest<T> request, PipelineConfiguration<T> configuration,
            PipelineExecutionContext context, Class<R> responseType) {

        
        context.addMetadata("targetResponseType", responseType);
        
        
        return step.execute(request, context)
                .then(Mono.just(context));
    }
}
