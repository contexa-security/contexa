package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import reactor.core.publisher.Mono;

public interface PipelineStep {

    <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context);

    /**
     * Returns the corresponding PipelineConfiguration.PipelineStep for this step.
     * Used for configuration matching without string-based switch statements.
     */
    PipelineConfiguration.PipelineStep getConfigStep();

    /**
     * Returns the step name derived from the config step enum.
     * Default implementation uses getConfigStep().name() to avoid duplication.
     */
    default String getStepName() {
        return getConfigStep().name();
    }

    default <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null;
    }

    default int getOrder() {
        return 100;
    }
} 