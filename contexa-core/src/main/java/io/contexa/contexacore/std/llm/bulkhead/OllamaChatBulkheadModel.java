package io.contexa.contexacore.std.llm.bulkhead;

import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;

public class OllamaChatBulkheadModel implements ChatModel {

    private static final String BULKHEAD_KEY = "ollama-chat";

    private final ChatModel delegate;
    private final String modelName;
    private final OllamaBulkheadSettings settings;

    public OllamaChatBulkheadModel(ChatModel delegate, String modelName, OllamaBulkheadSettings settings) {
        this.delegate = delegate;
        this.modelName = modelName;
        this.settings = settings;
    }

    @Override
    public ChatResponse call(Prompt prompt) {
        return OllamaBulkheadSupport.execute(BULKHEAD_KEY, "chat", modelName, settings, () -> delegate.call(prompt));
    }

    @Override
    public ChatOptions getDefaultOptions() {
        return delegate.getDefaultOptions();
    }

    @Override
    public Flux<ChatResponse> stream(Prompt prompt) {
        return Flux.defer(() -> {
            OllamaBulkheadSupport.tryAcquireForStreaming(BULKHEAD_KEY, modelName, settings);
            try {
                return delegate.stream(prompt)
                        .doFinally(signalType -> OllamaBulkheadSupport.releaseStreaming(BULKHEAD_KEY, settings));
            } catch (RuntimeException e) {
                OllamaBulkheadSupport.releaseStreaming(BULKHEAD_KEY, settings);
                return Flux.error(e);
            }
        });
    }
}