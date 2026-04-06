package io.contexa.autoconfigure.core.llm;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.handler.DefaultStreamingHandler;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.micrometer.observation.ObservationRegistry;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.observation.EmbeddingModelObservationConvention;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.OllamaEmbeddingModel;
import org.springframework.ai.ollama.api.OllamaApi;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.ai.ollama.api.OllamaEmbeddingOptions;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiEmbeddingModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.util.StringUtils;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Configuration
@RequiredArgsConstructor
@AutoConfigureAfter(name = {
        "org.springframework.ai.model.ollama.autoconfigure.OllamaEmbeddingAutoConfiguration",
        "org.springframework.ai.model.openai.autoconfigure.OpenAiEmbeddingAutoConfiguration"
})
@AutoConfigureBefore(name = {
        "org.springframework.ai.model.chat.client.autoconfigure.ChatClientAutoConfiguration",
        "org.springframework.ai.autoconfigure.chat.client.ChatClientAutoConfiguration",
        "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration"
})
@EnableConfigurationProperties(TieredLLMProperties.class)
public class CoreLLMTieredAutoConfiguration {

    private static final String DEFAULT_OLLAMA_CHAT_MODEL = "qwen3:8b";
    private static final String DEFAULT_OLLAMA_EMBEDDING_MODEL = "mxbai-embed-large";

    @Autowired
    private ContexaProperties contexaProperties;

    @Autowired
    private TieredLLMProperties tieredLLMProperties;

    @Bean(name = "contexaOllamaChatApi")
    @ConditionalOnProperty(prefix = "contexa.llm.chat.ollama", name = "base-url")
    @ConditionalOnMissingBean(name = "contexaOllamaChatApi")
    public OllamaApi contexaOllamaChatApi(
            ObjectProvider<RestClient.Builder> restClientBuilderProvider,
            ObjectProvider<WebClient.Builder> webClientBuilderProvider,
            ResponseErrorHandler responseErrorHandler) {

        return buildOllamaApi(
                resolveChatOllamaBaseUrl(),
                restClientBuilderProvider,
                webClientBuilderProvider,
                responseErrorHandler
        );
    }

    @Bean(name = "contexaOllamaChatModel")
    @ConditionalOnBean(name = "contexaOllamaChatApi")
    @ConditionalOnMissingBean(name = "contexaOllamaChatModel")
    public OllamaChatModel contexaOllamaChatModel(
            @Qualifier("contexaOllamaChatApi") OllamaApi ollamaApi) {

        OllamaChatOptions options = OllamaChatOptions.builder().build();
        if (StringUtils.hasText(contexaProperties.getLlm().getChat().getOllama().getModel())) {
            options.setModel(contexaProperties.getLlm().getChat().getOllama().getModel().trim());
        }
        else {
            options.setModel(DEFAULT_OLLAMA_CHAT_MODEL);
        }
        if (StringUtils.hasText(contexaProperties.getLlm().getChat().getOllama().getKeepAlive())) {
            options.setKeepAlive(contexaProperties.getLlm().getChat().getOllama().getKeepAlive().trim());
        }
        return OllamaChatModel.builder()
                .ollamaApi(ollamaApi)
                .defaultOptions(options)
                .build();
    }

    @Bean
    @Primary
    public ChatModel primaryChatModel(
            @Qualifier("contexaOllamaChatModel") ObjectProvider<OllamaChatModel> ollamaChatModelProvider,
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

        List<String> priorities = List.of(contexaProperties.getLlm().getChatModelPriority().split(","));
        for (String modelName : priorities) {
            String trimmedName = modelName.trim().toLowerCase();
            ChatModel model = availableModels.get(trimmedName);
            if (model != null) {
                return model;
            }
        }

        if (!availableModels.isEmpty()) {
            Map.Entry<String, ChatModel> firstEntry = availableModels.entrySet().iterator().next();
            log.error("No priority model found. Using {} (fallback)", firstEntry.getKey());
            return firstEntry.getValue();
        }

        log.error("No ChatModel available. LLM features will be disabled. " +
                "Configure contexa.llm.chat.ollama.*, spring.ai.anthropic.*, or spring.ai.openai.* to enable LLM.");
        return null;
    }

    @Bean
    @ConditionalOnMissingBean
    public ChatClient primaryChatClient(ChatModel primaryChatModel, AdvisorRegistry advisorRegistry) {
        ChatClient.Builder builder = ChatClient.builder(primaryChatModel);
        List<Advisor> advisors = advisorRegistry.getEnabled();
        if (!advisors.isEmpty()) {
            builder = builder.defaultAdvisors(advisors.toArray(new Advisor[0]));
        }
        return builder.build();
    }

    @Bean
    @ConditionalOnMissingBean(StreamingHandler.class)
    public StreamingHandler streamingHandler(JsonStreamingProcessor jsonStreamingProcessor) {
        return new DefaultStreamingHandler(tieredLLMProperties, jsonStreamingProcessor);
    }

    @Bean
    @Primary
    @ConditionalOnMissingBean(UnifiedLLMOrchestrator.class)
    public UnifiedLLMOrchestrator unifiedLLMOrchestrator(
            ModelSelectionStrategy modelSelectionStrategy,
            StreamingHandler streamingHandler,
            AdvisorRegistry advisorRegistry, ChatClient primaryChatClient) {

        return new UnifiedLLMOrchestrator(modelSelectionStrategy, streamingHandler, tieredLLMProperties, advisorRegistry);
    }

    @Bean(name = "llmClient")
    @ConditionalOnMissingBean(LLMClient.class)
    public LLMClient llmClient(UnifiedLLMOrchestrator unifiedLLMOrchestrator) {
        return unifiedLLMOrchestrator;
    }

    @Bean(name = "toolCapableLLMClient")
    @ConditionalOnMissingBean(ToolCapableLLMClient.class)
    public ToolCapableLLMClient toolCapableLLMClient(UnifiedLLMOrchestrator unifiedLLMOrchestrator) {
        return unifiedLLMOrchestrator;
    }

    @Bean(name = "contexaDedicatedEmbeddingOllamaApi")
    @ConditionalOnProperty(prefix = "contexa.llm.embedding.ollama", name = "dedicated-runtime-enabled", havingValue = "true")
    @ConditionalOnMissingBean(name = "contexaDedicatedEmbeddingOllamaApi")
    public OllamaApi contexaDedicatedEmbeddingOllamaApi(
            ObjectProvider<RestClient.Builder> restClientBuilderProvider,
            ObjectProvider<WebClient.Builder> webClientBuilderProvider,
            ResponseErrorHandler responseErrorHandler) {

        String baseUrl = resolveDedicatedEmbeddingOllamaBaseUrl();
        log.info("Enabling dedicated embedding Ollama runtime at {}", baseUrl);
        return buildOllamaApi(baseUrl, restClientBuilderProvider, webClientBuilderProvider, responseErrorHandler);
    }

    @Bean(name = "contexaDedicatedOllamaEmbeddingModel")
    @ConditionalOnProperty(prefix = "contexa.llm.embedding.ollama", name = "dedicated-runtime-enabled", havingValue = "true")
    @ConditionalOnMissingBean(name = "contexaDedicatedOllamaEmbeddingModel")
    public OllamaEmbeddingModel contexaDedicatedOllamaEmbeddingModel(
            @Qualifier("contexaDedicatedEmbeddingOllamaApi") OllamaApi ollamaApi,
            ObjectProvider<ObservationRegistry> observationRegistry,
            ObjectProvider<EmbeddingModelObservationConvention> observationConvention) {

        return buildOllamaEmbeddingModel(ollamaApi, observationRegistry, observationConvention, resolveEmbeddingModel());
    }

    @Bean(name = "contexaSharedOllamaEmbeddingModel")
    @ConditionalOnBean(name = "contexaOllamaChatApi")
    @ConditionalOnMissingBean(name = "contexaSharedOllamaEmbeddingModel")
    public OllamaEmbeddingModel contexaSharedOllamaEmbeddingModel(
            @Qualifier("contexaOllamaChatApi") OllamaApi ollamaApi,
            ObjectProvider<ObservationRegistry> observationRegistry,
            ObjectProvider<EmbeddingModelObservationConvention> observationConvention) {

        return buildOllamaEmbeddingModel(ollamaApi, observationRegistry, observationConvention, resolveEmbeddingModel());
    }

    @Bean(name = {"primaryEmbeddingModel", "embeddingModel"})
    @Primary
    @ConditionalOnMissingBean(name = {"primaryEmbeddingModel", "embeddingModel"})
    @Conditional(AnyEmbeddingModelAvailableCondition.class)
    public EmbeddingModel primaryEmbeddingModel(
            @Qualifier("contexaDedicatedOllamaEmbeddingModel") ObjectProvider<OllamaEmbeddingModel> dedicatedOllamaEmbeddingModelProvider,
            @Qualifier("contexaSharedOllamaEmbeddingModel") ObjectProvider<OllamaEmbeddingModel> sharedOllamaEmbeddingModelProvider,
            ObjectProvider<OpenAiEmbeddingModel> openAiEmbeddingModelProvider) {

        Map<String, EmbeddingModel> availableModels = new HashMap<>();

        OllamaEmbeddingModel dedicatedOllamaEmbedding = dedicatedOllamaEmbeddingModelProvider.getIfAvailable();
        OllamaEmbeddingModel sharedOllamaEmbedding = sharedOllamaEmbeddingModelProvider.getIfAvailable();
        if (dedicatedOllamaEmbedding != null) {
            availableModels.put("ollama", dedicatedOllamaEmbedding);
        }
        else if (sharedOllamaEmbedding != null) {
            availableModels.put("ollama", sharedOllamaEmbedding);
        }

        OpenAiEmbeddingModel openAiEmbedding = openAiEmbeddingModelProvider.getIfAvailable();
        if (openAiEmbedding != null) {
            availableModels.put("openai", openAiEmbedding);
        }

        List<String> priorities = List.of(contexaProperties.getLlm().getEmbeddingModelPriority().split(","));
        for (String modelName : priorities) {
            String trimmedName = modelName.trim().toLowerCase();
            EmbeddingModel model = availableModels.get(trimmedName);
            if (model != null) {
                return model;
            }
        }

        if (!availableModels.isEmpty()) {
            Map.Entry<String, EmbeddingModel> firstEntry = availableModels.entrySet().iterator().next();
            log.error("No priority model found. Using {} (fallback)", firstEntry.getKey());
            return firstEntry.getValue();
        }

        log.error("No EmbeddingModel available. Embedding features will be disabled. " +
                "Configure contexa.llm.embedding.ollama.*, contexa.llm.chat.ollama.*, or spring.ai.openai.* to enable embedding.");
        return null;
    }

    @PostConstruct
    public void init() {
    }

    private OllamaApi buildOllamaApi(
            String baseUrl,
            ObjectProvider<RestClient.Builder> restClientBuilderProvider,
            ObjectProvider<WebClient.Builder> webClientBuilderProvider,
            ResponseErrorHandler responseErrorHandler
    ) {
        return OllamaApi.builder()
                .baseUrl(baseUrl)
                .restClientBuilder(restClientBuilderProvider.getIfAvailable(RestClient::builder))
                .webClientBuilder(webClientBuilderProvider.getIfAvailable(WebClient::builder))
                .responseErrorHandler(responseErrorHandler)
                .build();
    }

    private OllamaEmbeddingModel buildOllamaEmbeddingModel(
            OllamaApi ollamaApi,
            ObjectProvider<ObservationRegistry> observationRegistry,
            ObjectProvider<EmbeddingModelObservationConvention> observationConvention,
            String model
    ) {
        OllamaEmbeddingOptions options = OllamaEmbeddingOptions.builder()
                .model(model)
                .build();

        OllamaEmbeddingModel embeddingModel = OllamaEmbeddingModel.builder()
                .ollamaApi(ollamaApi)
                .defaultOptions(options)
                .observationRegistry(observationRegistry.getIfUnique(() -> ObservationRegistry.NOOP))
                .build();

        observationConvention.ifAvailable(embeddingModel::setObservationConvention);
        return embeddingModel;
    }

    private String resolveChatOllamaBaseUrl() {
        String baseUrl = contexaProperties.getLlm().getChat().getOllama().getBaseUrl();
        if (!StringUtils.hasText(baseUrl)) {
            throw new IllegalStateException("contexa.llm.chat.ollama.base-url must be configured when Ollama chat runtime is enabled");
        }
        return baseUrl.trim();
    }

    private String resolveDedicatedEmbeddingOllamaBaseUrl() {
        ContexaProperties.Llm.Embedding.Ollama ollama = contexaProperties.getLlm().getEmbedding().getOllama();
        if (!ollama.isDedicatedRuntimeEnabled()) {
            throw new IllegalStateException("Dedicated embedding runtime requested without contexa.llm.embedding.ollama.dedicated-runtime-enabled=true");
        }
        if (!StringUtils.hasText(ollama.getBaseUrl())) {
            throw new IllegalStateException("contexa.llm.embedding.ollama.base-url must be configured when dedicated embedding runtime is enabled");
        }
        return ollama.getBaseUrl().trim();
    }

    private String resolveEmbeddingModel() {
        String configuredModel = contexaProperties.getLlm().getEmbedding().getOllama().getModel();
        if (StringUtils.hasText(configuredModel)) {
            return configuredModel.trim();
        }
        return DEFAULT_OLLAMA_EMBEDDING_MODEL;
    }
}