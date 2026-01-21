package io.contexa.contexacore.std.llm.handler;

import io.contexa.contexacore.std.llm.core.ExecutionContext;
import org.springframework.ai.chat.client.ChatClient;
import reactor.core.publisher.Flux;

public interface StreamingHandler {

    Flux<String> handleStreaming(ChatClient chatClient, ExecutionContext context);

    Flux<String> handleStreamingWithTools(ChatClient chatClient, ExecutionContext context);
}