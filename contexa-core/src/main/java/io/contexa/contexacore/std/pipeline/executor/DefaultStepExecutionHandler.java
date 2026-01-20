package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.PipelineStep;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import reactor.core.publisher.Mono;

public class DefaultStepExecutionHandler implements StepExecutionHandler {
    @Override
    public boolean canHandle(PipelineStep step) {
        return true;

    }

    @Override
    public <T extends DomainContext, R extends AIResponse> Mono<PipelineExecutionContext> execute(
            PipelineStep step, AIRequest<T> request, PipelineConfiguration<T> configuration,
            PipelineExecutionContext context, Class<R> responseType) {
        return step.execute(request, context).thenReturn(context);
    }
}