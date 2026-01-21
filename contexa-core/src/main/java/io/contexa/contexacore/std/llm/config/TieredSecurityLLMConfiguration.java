package io.contexa.contexacore.std.llm.config;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.core.LLMOperations;
import io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.handler.DefaultStreamingHandler;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.model.chat.client.autoconfigure.ChatClientAutoConfiguration;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.OllamaEmbeddingModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiEmbeddingModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Configuration
@RequiredArgsConstructor
@AutoConfigureBefore(ChatClientAutoConfiguration.class)
public class TieredSecurityLLMConfiguration {

    @Value("${spring.ai.chat.model.priority:ollama,anthropic,openai}")
    private String chatModelPriority;

    @Value("${spring.ai.embedding.model.priority:ollama,openai}")
    private String embeddingModelPriority;

    @Autowired
    private TieredLLMProperties tieredLLMProperties;

    @Bean(name = "tinyLlamaChatModel")
    @ConditionalOnMissingBean(name = "tinyLlamaChatModel")
    public ChatModel tinyLlamaChatModel(
            @Autowired(required = false) OllamaChatModel ollamaChatModel,
            @Autowired(required = false) AnthropicChatModel anthropicChatModel,
            @Autowired(required = false) OpenAiChatModel openAiChatModel) {

        if (ollamaChatModel != null) {

                        return ollamaChatModel;
        }

        log.warn("  ⚠ Ollama ChatModel이 구성되지 않았습니다. 폴백 모델로 시도");

        if (anthropicChatModel != null) {
                        return anthropicChatModel;
        }

        if (openAiChatModel != null) {
                        return openAiChatModel;
        }

        log.warn("  ⚠ 모든 모델 제공자가 사용 불가능합니다. Layer 1 모델이 null로 설정됩니다");
        return null;
    }

    @Bean(name = "llama31ChatModel")
    @ConditionalOnMissingBean(name = "llama31ChatModel")
    public ChatModel llama31ChatModel(
            @Autowired(required = false) OllamaChatModel ollamaChatModel,
            @Autowired(required = false) AnthropicChatModel anthropicChatModel,
            @Autowired(required = false) OpenAiChatModel openAiChatModel) {

        if (ollamaChatModel != null) {

                        return ollamaChatModel;
        }

        log.warn("  ⚠ Ollama ChatModel이 구성되지 않았습니다. 폴백 모델로 시도");

        if (anthropicChatModel != null) {
                        return anthropicChatModel;
        }

        if (openAiChatModel != null) {
                        return openAiChatModel;
        }

        log.warn("  ⚠ 모든 모델 제공자가 사용 불가능합니다. Layer 2 모델이 null로 설정됩니다");
        return null;
    }

    @Bean(name = "claudeOpusChatModel")
    @ConditionalOnMissingBean(name = "claudeOpusChatModel")
    public ChatModel claudeOpusChatModel(
            @Autowired(required = false) AnthropicChatModel anthropicChatModel,
            @Value("${spring.ai.security.layer2.backup.model:claude-3-5-sonnet-20241022}") String modelName) {

        if (anthropicChatModel != null) {
                        return anthropicChatModel;
        }

        log.warn("  - Anthropic ChatModel을 찾을 수 없습니다. API 키 확인 필요");
        return null;
    }

    @Bean(name = "gpt4ChatModel")
    @ConditionalOnMissingBean(name = "gpt4ChatModel")
    public ChatModel gpt4ChatModel(
            @Autowired(required = false) OpenAiChatModel openAiChatModel,
            @Value("${spring.ai.security.layer2.backup.model:gpt-4o}") String modelName) {

        if (openAiChatModel != null) {
                        return openAiChatModel;
        }

        log.warn("  - OpenAI ChatModel을 찾을 수 없습니다. API 키 확인 필요");
        return null;
    }

    @Bean
    @Primary
    public ChatModel primaryChatModel(
            ObjectProvider<OllamaChatModel> ollamaChatModelProvider,
            ObjectProvider<AnthropicChatModel> anthropicChatModelProvider,
            ObjectProvider<OpenAiChatModel> openAiChatModelProvider) {

        Map<String, ChatModel> availableModels = new HashMap<>();

        OllamaChatModel ollamaModel = ollamaChatModelProvider.getIfAvailable();
        if (ollamaModel != null) {
            availableModels.put("ollama", ollamaModel);
        }

        AnthropicChatModel anthropicModel = anthropicChatModelProvider.getIfAvailable();
        if (anthropicModel != null) {
            availableModels.put("anthropic", anthropicModel);
        }

        OpenAiChatModel openAiModel = openAiChatModelProvider.getIfAvailable();
        if (openAiModel != null) {
            availableModels.put("openai", openAiModel);
        }

        List<String> priorities = List.of(chatModelPriority.split(","));
        for (String modelName : priorities) {
            String trimmedName = modelName.trim().toLowerCase();
            ChatModel model = availableModels.get(trimmedName);
            if (model != null) {
                                return model;
            }
        }

        if (!availableModels.isEmpty()) {
            Map.Entry<String, ChatModel> firstEntry = availableModels.entrySet().iterator().next();
            log.warn("  ⚠ 우선순위 모델 없음. {} 사용 (fallback)", firstEntry.getKey());
            return firstEntry.getValue();
        }

        log.error("  사용 가능한 ChatModel이 없습니다!");
        throw new IllegalStateException("No ChatModel available. Please configure at least one AI provider.");
    }

    @Bean
    @ConditionalOnMissingBean(StreamingHandler.class)
    public StreamingHandler streamingHandler() {
                return new DefaultStreamingHandler(tieredLLMProperties);
    }

    @Bean
    @Primary
    public UnifiedLLMOrchestrator unifiedLLMOrchestrator(
            ModelSelectionStrategy modelSelectionStrategy,
            StreamingHandler streamingHandler) {

        return new UnifiedLLMOrchestrator(modelSelectionStrategy, streamingHandler, tieredLLMProperties);
    }

    @Bean
    public LLMOperations llmOperations(UnifiedLLMOrchestrator unifiedLLMOrchestrator) {
                return unifiedLLMOrchestrator;
    }

    @Bean(name = "llmClient")
    public LLMClient llmClient(UnifiedLLMOrchestrator unifiedLLMOrchestrator) {
                return unifiedLLMOrchestrator;
    }

    @Bean(name = "toolCapableLLMClient")
    public ToolCapableLLMClient toolCapableLLMClient(UnifiedLLMOrchestrator unifiedLLMOrchestrator) {
                return unifiedLLMOrchestrator;
    }

    @Bean(name = "primaryEmbeddingModel")
    @Primary
    @ConditionalOnMissingBean(name = "primaryEmbeddingModel")
    public EmbeddingModel primaryEmbeddingModel(
            ObjectProvider<OllamaEmbeddingModel> ollamaEmbeddingModelProvider,
            ObjectProvider<OpenAiEmbeddingModel> openAiEmbeddingModelProvider) {

        Map<String, EmbeddingModel> availableModels = new HashMap<>();

        OllamaEmbeddingModel ollamaEmbedding = ollamaEmbeddingModelProvider.getIfAvailable();
        if (ollamaEmbedding != null) {
            availableModels.put("ollama", ollamaEmbedding);
        }

        OpenAiEmbeddingModel openAiEmbedding = openAiEmbeddingModelProvider.getIfAvailable();
        if (openAiEmbedding != null) {
            availableModels.put("openai", openAiEmbedding);
        }

        List<String> priorities = List.of(embeddingModelPriority.split(","));
        for (String modelName : priorities) {
            String trimmedName = modelName.trim().toLowerCase();
            EmbeddingModel model = availableModels.get(trimmedName);
            if (model != null) {
                                return model;
            }
        }

        if (!availableModels.isEmpty()) {
            Map.Entry<String, EmbeddingModel> firstEntry = availableModels.entrySet().iterator().next();
            log.warn("  ⚠ 우선순위 모델 없음. {} 사용 (fallback)", firstEntry.getKey());
            return firstEntry.getValue();
        }

        throw new IllegalStateException("No EmbeddingModel available. Please configure at least one embedding provider.");
    }

    @Bean
    @ConditionalOnMissingBean(ChatClient.Builder.class)
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "enabled", havingValue = "false", matchIfMissing = true)
    public ChatClient.Builder chatClientBuilder(ChatModel primaryChatModel) {
                return ChatClient.builder(primaryChatModel);
    }

    @Bean
    @ConditionalOnMissingBean(name = "defaultChatClient")
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "enabled", havingValue = "false")
    public ChatClient defaultChatClient(ChatClient.Builder builder) {
                return builder.build();
    }

    @PostConstruct
    public void init() {
                                                                                                                                                                            }
}