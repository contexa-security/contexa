package io.contexa.contexacore.std.llm.config;

import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface LLMClient {

    Mono<String> call(Prompt prompt);

    <T> Mono<T> entity(Prompt prompt, Class<T> targetType);

    Flux<String> stream(Prompt prompt);
}
