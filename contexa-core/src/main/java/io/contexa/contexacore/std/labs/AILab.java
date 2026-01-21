package io.contexa.contexacore.std.labs;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AILab<Req, Res> {

    String getLabId();

    String getLabName();

    Res process(Req request);

    Mono<Res> processAsync(Req request);

    Flux<String> processStream(Req request);

    default boolean supportsStreaming() {
        return false;
    }

    default boolean isActive() {
        return true;
    }

    default boolean canProcess(Req request) {
        return request != null && isActive();
    }
}