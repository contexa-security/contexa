package io.contexa.contexacore.std.llm.core;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;


public interface LLMOperations {
    
    
    Mono<String> execute(ExecutionContext context);
    
    
    Flux<String> stream(ExecutionContext context);
    
    
    <T> Mono<T> executeEntity(ExecutionContext context, Class<T> targetType);
}