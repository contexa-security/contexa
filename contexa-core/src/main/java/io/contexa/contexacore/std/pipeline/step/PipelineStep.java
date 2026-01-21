package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import reactor.core.publisher.Mono;

public interface PipelineStep {

    <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context);

    String getStepName();

    default <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null;
    }

    default int getOrder() {
        return 100;
    }
} 