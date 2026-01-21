package io.contexa.contexacore.std.strategy;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.enums.DiagnosisType;
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

    default boolean canHandle(AIRequest<T> request) {
        return request.getDiagnosisType() == getSupportedType();
    }

    default String getDescription() {
        return getSupportedType().getDescription();
    }

    default io.contexa.contexacore.std.pipeline.PipelineConfiguration<T> suggestPipelineConfiguration(
            AIRequest<T> request,
            io.contexa.contexacore.std.pipeline.analyzer.RequestCharacteristics characteristics) {
        
        return null;
    }
}
