package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
public class ContextRetrievalStep implements PipelineStep {

    private final ContextRetrieverRegistry contextRetrieverRegistry;

    public ContextRetrievalStep(ContextRetrieverRegistry contextRetrieverRegistry) {
        this.contextRetrieverRegistry = contextRetrieverRegistry;
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            
            ContextRetriever contextRetriever = contextRetrieverRegistry.getRetriever(request.getContext());
            ContextRetriever.ContextRetrievalResult contextResult = contextRetriever.retrieveContext(request);

            context.addStepResult(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL, contextResult);

            String debugContextInfo = contextResult != null ? contextResult.getContextInfo() : "null";
            
            return contextResult;
        });
    }

    @Override
    public String getStepName() {
        return "CONTEXT_RETRIEVAL";
    }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null && request.getContext() != null;
    }

    @Override
    public int getOrder() {
        return 1; 
    }
}