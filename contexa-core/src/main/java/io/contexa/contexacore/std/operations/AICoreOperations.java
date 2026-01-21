package io.contexa.contexacore.std.operations;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

public interface AICoreOperations<T extends DomainContext> {

    <R extends AIResponse> Mono<R> process(AIRequest<T> request, Class<R> responseType);

    Flux<String> processStream(AIRequest<T> request);

    <R extends AIResponse> Flux<R> executeStreamTyped(AIRequest<T> request, Class<R> responseType);

    <R extends AIResponse> Mono<List<R>> executeBatch(List<AIRequest<T>> requests, Class<R> responseType);

    <T1 extends DomainContext, T2 extends DomainContext> 
    Mono<AIResponse> executeMixed(List<AIRequest<T1>> requests1, List<AIRequest<T2>> requests2);

}