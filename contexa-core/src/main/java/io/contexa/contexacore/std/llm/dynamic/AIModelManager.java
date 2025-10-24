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

/**
 * AI 모델을 동적으로 선택하여 사용할 수 있는 관리 서비스
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AIModelManager {

    // 사용 가능한 모든 Chat 모델
    @Autowired(required = false)
    private AnthropicChatModel anthropicChatModel;

    @Autowired(required = false)
    private OllamaChatModel ollamaChatModel;

    @Autowired(required = false)
    private OpenAiChatModel openAiChatModel;

    // 사용 가능한 모든 Embedding 모델
    @Autowired(required = false)
    private OllamaEmbeddingModel ollamaEmbeddingModel;

    @Autowired(required = false)
    private OpenAiEmbeddingModel openAiEmbeddingModel;

    // ChatClient 캐시
    private final Map<String, ChatClient> chatClientCache = new ConcurrentHashMap<>();

    /**
     * 지정된 모델로 채팅 요청을 실행
     */
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

    /**
     * 지정된 모델로 임베딩 생성
     */
    public EmbeddingResponse embed(AIModelType modelType, String text) {
        EmbeddingModel model = getEmbeddingModel(modelType);
        if (model == null) {
            throw new IllegalArgumentException("EmbeddingModel not available: " + modelType);
        }

        log.info("Using {} for embedding request", modelType);
        return model.call(new org.springframework.ai.embedding.EmbeddingRequest(List.of(text), null));
    }

    /**
     * 작업 유형에 따라 최적의 모델을 자동 선택
     */
    public ChatResponse chatWithBestModel(TaskType taskType, String prompt) {
        AIModelType bestModel = selectBestModelForTask(taskType);
        return chat(bestModel, prompt);
    }

    /**
     * 사용 가능한 모든 모델로 동시에 요청하고 가장 빠른 응답 반환
     */
    public ChatResponse chatWithFastest(String prompt) {
        List<AIModelType> availableModels = getAvailableChatModels();
        if (availableModels.isEmpty()) {
            throw new IllegalStateException("No chat models available");
        }

        // 간단한 구현: 첫 번째 사용 가능한 모델 사용
        // 실제로는 CompletableFuture를 사용한 병렬 처리 구현 가능
        return chat(availableModels.get(0), prompt);
    }

    /**
     * 모델 상태 확인
     */
    public Map<String, Boolean> getModelStatus() {
        return Map.of(
                "anthropic", anthropicChatModel != null,
                "ollama", ollamaChatModel != null,
                "openai", openAiChatModel != null,
                "ollama-embedding", ollamaEmbeddingModel != null,
                "openai-embedding", openAiEmbeddingModel != null
        );
    }

    /**
     * 특정 작업에 최적화된 모델 선택 로직
     */
    private AIModelType selectBestModelForTask(TaskType taskType) {
        switch (taskType) {
            case CODE_GENERATION:
                // 코드 생성은 Claude가 최고
                if (anthropicChatModel != null) return AIModelType.ANTHROPIC;
                if (openAiChatModel != null) return AIModelType.OPENAI;
                return AIModelType.OLLAMA;

            case QUICK_RESPONSE:
                // 빠른 응답은 로컬 모델이 유리
                if (ollamaChatModel != null) return AIModelType.OLLAMA;
                return getFirstAvailableModel();

            case CREATIVE_WRITING:
                // 창의적 글쓰기는 Claude나 GPT가 우수
                if (anthropicChatModel != null) return AIModelType.ANTHROPIC;
                if (openAiChatModel != null) return AIModelType.OPENAI;
                return AIModelType.OLLAMA;

            case ANALYSIS:
                // 분석 작업은 모든 모델이 적합
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

    /**
     * AI 모델 타입
     */
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

    /**
     * 작업 유형
     */
    public enum TaskType {
        CODE_GENERATION,    // 코드 생성
        QUICK_RESPONSE,     // 빠른 응답
        CREATIVE_WRITING,   // 창의적 글쓰기
        ANALYSIS,          // 분석
        TRANSLATION,       // 번역
        SUMMARIZATION      // 요약
    }
}
