package io.contexa.contexacore.std.strategy;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AIStrategy<T extends DomainContext, R extends AIResponse> {

    DiagnosisType getSupportedType();

    int getPriority();

    R execute(AIRequest<T> request, Class<R> responseType) throws DiagnosisException;

    Mono<R> executeAsync(AIRequest<T> request, Class<R> responseType) throws DiagnosisException;

    Flux<String> executeStream(AIRequest<T> request, Class<R> responseType) throws DiagnosisException;

    default boolean supportsStreaming() {
        return false;
    }
}
