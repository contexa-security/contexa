package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface PipelineExecutor {

    <T extends DomainContext, R extends AIResponse> Mono<R> execute(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            Class<R> responseType);

    <T extends DomainContext> Flux<String> executeStream(
            AIRequest<T> request, 
            PipelineConfiguration<T> configuration);

    String getSupportedDomain();

    <T extends DomainContext> boolean supportsConfiguration(PipelineConfiguration<T> configuration);

    default int getPriority() {
        return 100; 
    }
} 