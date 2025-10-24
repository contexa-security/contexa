package io.contexa.contexacore.std.llm.config;

import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * 도구 호출 기능을 지원하는 LLM 클라이언트 인터페이스
 *
 * 기존 LLMClient 인터페이스를 확장하여 도구 호출 기능을 추가합니다.
 */
public interface ToolCapableLLMClient extends LLMClient {

    /**
     * LLM을 호출하여 단일 응답을 받습니다. 도구 호출 기능을 포함합니다.
     * @param prompt AI 모델에 전달할 프롬프트
     * @param toolProviders 도구 제공자 객체 목록
     * @return 전체 응답 문자열을 포함하는 Mono
     */
    Mono<String> callTools(Prompt prompt, List<Object> toolProviders);
    Mono<String> callToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks);

    Mono<ChatResponse> callToolsResponse(Prompt prompt, List<Object> toolProviders);
    Mono<ChatResponse> callToolCallbacksResponse(Prompt prompt, ToolCallback[] toolCallbacks);

    /**
     * LLM을 호출하여 응답을 스트리밍 방식으로 받습니다. 도구 호출 기능을 포함합니다.
     * @param prompt AI 모델에 전달할 프롬프트
     * @param toolProviders 도구 제공자 객체 목록
     * @return 응답 청크(chunk)를 포함하는 Flux
     */
    Flux<String> streamTools(Prompt prompt, List<Object> toolProviders);
    Flux<String> streamToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks);
}
