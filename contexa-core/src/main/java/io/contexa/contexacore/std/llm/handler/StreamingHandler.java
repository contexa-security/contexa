package io.contexa.contexacore.std.llm.handler;

import io.contexa.contexacore.std.llm.client.ExecutionContext;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import reactor.core.publisher.Flux;

public interface StreamingHandler {

    Flux<String> handleStreaming(ChatClient chatClient, ExecutionContext context, ChatModel selectedModel);

    Flux<String> handleStreamingWithTools(ChatClient chatClient, ExecutionContext context, ChatModel selectedModel);
}