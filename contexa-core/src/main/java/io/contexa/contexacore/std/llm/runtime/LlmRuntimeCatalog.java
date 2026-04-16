package io.contexa.contexacore.std.llm.runtime;

import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;

import java.util.List;
import java.util.Optional;

public interface LlmRuntimeCatalog {

    List<LlmRuntimeBinding> getChatBindings();

    List<LlmRuntimeBinding> getEmbeddingBindings();

    Optional<LlmRuntimeBinding> findChatBinding(String selector);

    Optional<LlmRuntimeBinding> findEmbeddingBinding(String selector);

    ChatModel resolveChatModel(String selector);

    EmbeddingModel resolveEmbeddingModel(String selector);

    Optional<ChatModel> resolvePrimaryChatModel(String priorityConfig);

    Optional<EmbeddingModel> resolvePrimaryEmbeddingModel(String priorityConfig);

    Optional<ChatModel> resolveSpringPrimaryChatModel();

    Optional<EmbeddingModel> resolveSpringPrimaryEmbeddingModel();
}