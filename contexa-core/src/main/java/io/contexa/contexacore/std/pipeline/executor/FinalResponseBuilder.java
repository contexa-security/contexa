package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;

class FinalResponseBuilder {
    public <T extends DomainContext, R extends AIResponse> R build(
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<R> responseType) {

        R result = context.getStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, responseType);
        if (result == null) {
            throw new IllegalStateException("POSTPROCESSING step must return a result for request: " + request.getRequestId());
        }
        return result;
    }
}
