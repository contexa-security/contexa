package io.contexa.contexacore.std.llm.config;

import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * LLM 클라이언트 인터페이스
 *
 * 의존성 역전 원칙 (DIP):
 * - LLMExecutionStep은 이제 이 인터페이스에만 의존하며,
 * 실제 구현 기술(Spring AI, OpenAI API 등)로부터 완전히 분리됩니다.
 */
public interface LLMClient {

    /**
     * LLM을 호출하여 단일 응답을 받습니다.
     * @param prompt AI 모델에 전달할 프롬프트
     * @return 전체 응답 문자열을 포함하는 Mono
     */
    Mono<String> call(Prompt prompt);

    <T> Mono<T> entity(Prompt prompt, Class<T> targetType);

    /**
     * LLM을 호출하여 응답을 스트리밍 방식으로 받습니다.
     * @param prompt AI 모델에 전달할 프롬프트
     * @return 응답 청크(chunk)를 포함하는 Flux
     */
    Flux<String> stream(Prompt prompt);
}
