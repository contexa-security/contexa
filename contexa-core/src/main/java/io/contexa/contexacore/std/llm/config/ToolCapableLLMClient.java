package io.contexa.contexacore.std.llm.config;

import io.contexa.contexacore.std.llm.config.LLMClient;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

public interface ToolCapableLLMClient extends LLMClient {

    Mono<String> callTools(Prompt prompt, List<Object> toolProviders);
    Mono<String> callToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks);

    Mono<ChatResponse> callToolsResponse(Prompt prompt, List<Object> toolProviders);
    Mono<ChatResponse> callToolCallbacksResponse(Prompt prompt, ToolCallback[] toolCallbacks);

    Flux<String> streamTools(Prompt prompt, List<Object> toolProviders);
    Flux<String> streamToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks);
}
