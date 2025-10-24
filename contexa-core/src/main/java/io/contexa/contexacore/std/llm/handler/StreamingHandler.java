package io.contexa.contexacore.std.llm.handler;

import io.contexa.contexacore.std.llm.core.ExecutionContext;
import org.springframework.ai.chat.client.ChatClient;
import reactor.core.publisher.Flux;

/**
 * 스트리밍 처리 인터페이스
 * 
 * SRP: 스트리밍 로직만 담당
 * OCP: 새로운 스트리밍 전략 추가 가능
 */
public interface StreamingHandler {
    
    /**
     * ChatClient와 ExecutionContext로부터 스트리밍 처리
     * 
     * @param chatClient 구성된 ChatClient
     * @param context 실행 컨텍스트
     * @return 스트리밍 응답
     */
    Flux<String> handleStreaming(ChatClient chatClient, ExecutionContext context);
    
    /**
     * 도구 실행이 포함된 스트리밍 처리
     * 
     * @param chatClient 구성된 ChatClient
     * @param context 실행 컨텍스트
     * @return 도구 실행 결과가 포함된 스트리밍 응답
     */
    Flux<String> handleStreamingWithTools(ChatClient chatClient, ExecutionContext context);
}