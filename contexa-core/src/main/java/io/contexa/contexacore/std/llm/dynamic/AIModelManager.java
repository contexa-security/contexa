package io.contexa.contexacore.std.llm.dynamic;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.OllamaEmbeddingModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiEmbeddingModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
@RequiredArgsConstructor
public class AIModelManager {

    
    @Autowired(required = false)
    private AnthropicChatModel anthropicChatModel;

    @Autowired(required = false)
    private OllamaChatModel ollamaChatModel;

    @Autowired(required = false)
    private OpenAiChatModel openAiChatModel;

    
    @Autowired(required = false)
    private OllamaEmbeddingModel ollamaEmbeddingModel;

    @Autowired(required = false)
    private OpenAiEmbeddingModel openAiEmbeddingModel;

    
    private final Map<String, ChatClient> chatClientCache = new ConcurrentHashMap<>();

    
    public ChatResponse chat(AIModelType modelType, String prompt) {
        ChatModel model = getChatModel(modelType);
        if (model == null) {
            throw new IllegalArgumentException("ChatModel not available: " + modelType);
        }

        log.info("Using {} for chat request", modelType);
        ChatClient client = getChatClient(modelType);

        return client.prompt()
                .user(prompt)
                .call()
                .chatResponse();
    }

    
    public EmbeddingResponse embed(AIModelType modelType, String text) {
        EmbeddingModel model = getEmbeddingModel(modelType);
        if (model == null) {
            throw new IllegalArgumentException("EmbeddingModel not available: " + modelType);
        }

        log.info("Using {} for embedding request", modelType);
        return model.call(new org.springframework.ai.embedding.EmbeddingRequest(List.of(text), null));
    }

    
    public ChatResponse chatWithBestModel(TaskType taskType, String prompt) {
        AIModelType bestModel = selectBestModelForTask(taskType);
        return chat(bestModel, prompt);
    }

    
    public ChatResponse chatWithFastest(String prompt) {
        List<AIModelType> availableModels = getAvailableChatModels();
        if (availableModels.isEmpty()) {
            throw new IllegalStateException("No chat models available");
        }

        
        
        return chat(availableModels.get(0), prompt);
    }

    
    public Map<String, Boolean> getModelStatus() {
        return Map.of(
                "anthropic", anthropicChatModel != null,
                "ollama", ollamaChatModel != null,
                "openai", openAiChatModel != null,
                "ollama-embedding", ollamaEmbeddingModel != null,
                "openai-embedding", openAiEmbeddingModel != null
        );
    }

    
    private AIModelType selectBestModelForTask(TaskType taskType) {
        switch (taskType) {
            case CODE_GENERATION:
                
                if (anthropicChatModel != null) return AIModelType.ANTHROPIC;
                if (openAiChatModel != null) return AIModelType.OPENAI;
                return AIModelType.OLLAMA;

            case QUICK_RESPONSE:
                
                if (ollamaChatModel != null) return AIModelType.OLLAMA;
                return getFirstAvailableModel();

            case CREATIVE_WRITING:
                
                if (anthropicChatModel != null) return AIModelType.ANTHROPIC;
                if (openAiChatModel != null) return AIModelType.OPENAI;
                return AIModelType.OLLAMA;

            case ANALYSIS:
                
                return getFirstAvailableModel();

            default:
                return getFirstAvailableModel();
        }
    }

    private ChatModel getChatModel(AIModelType type) {
        switch (type) {
            case ANTHROPIC:
                return anthropicChatModel;
            case OLLAMA:
                return ollamaChatModel;
            case OPENAI:
                return openAiChatModel;
            default:
                return null;
        }
    }

    private EmbeddingModel getEmbeddingModel(AIModelType type) {
        switch (type) {
            case OLLAMA:
                return ollamaEmbeddingModel;
            case OPENAI:
                return openAiEmbeddingModel;
            default:
                return null;
        }
    }

    private ChatClient getChatClient(AIModelType type) {
        return chatClientCache.computeIfAbsent(type.name(), k -> {
            ChatModel model = getChatModel(type);
            return model != null ? ChatClient.builder(model).build() : null;
        });
    }

    private List<AIModelType> getAvailableChatModels() {
        return List.of(AIModelType.values()).stream()
                .filter(type -> getChatModel(type) != null)
                .toList();
    }

    private AIModelType getFirstAvailableModel() {
        List<AIModelType> available = getAvailableChatModels();
        if (available.isEmpty()) {
            throw new IllegalStateException("No chat models available");
        }
        return available.get(0);
    }

    
    public enum AIModelType {
        ANTHROPIC("Claude"),
        OLLAMA("Ollama"),
        OPENAI("OpenAI");

        private final String displayName;

        AIModelType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    
    public enum TaskType {
        CODE_GENERATION,    
        QUICK_RESPONSE,     
        CREATIVE_WRITING,   
        ANALYSIS,          
        TRANSLATION,       
        SUMMARIZATION      
    }
}
