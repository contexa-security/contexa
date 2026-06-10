package io.contexa.autoconfigure.core.llm;

import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.handler.DefaultStreamingHandler;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.micrometer.observation.ObservationRegistry;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
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
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Arrays;
import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
@AutoConfigureAfter(name = {
        "org.springframework.ai.model.ollama.autoconfigure.OllamaChatAutoConfiguration",
        "org.springframework.ai.model.ollama.autoconfigure.OllamaEmbeddingAutoConfiguration",
        "org.springframework.ai.model.openai.autoconfigure.OpenAiChatAutoConfiguration",
        "org.springframework.ai.model.openai.autoconfigure.OpenAiEmbeddingAutoConfiguration",
        "org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration"
})
@AutoConfigureBefore(name = {
        "org.springframework.ai.model.chat.client.autoconfigure.ChatClientAutoConfiguration",
        "org.springframework.ai.autoconfigure.chat.client.ChatClientAutoConfiguration",
        "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration"
})
@EnableConfigurationProperties({TieredLLMProperties.class, ContexaLlmSelectionProperties.class})
public class CoreLLMTieredAutoConfiguration {

    private static final String DEFAULT_OLLAMA_CHAT_MODEL = "qwen3:8b";
    private static final String DEFAULT_OLLAMA_EMBEDDING_MODEL = "mxbai-embed-large";

    @Autowired
    private ContexaProperties contexaProperties;

    @Autowired
    private TieredLLMProperties tieredLLMProperties;

    @Autowired
    private ContexaLlmSelectionProperties contexaLlmSelectionProperties;



    @Bean(name = "primaryChatModel")
    @Primary
    @ConditionalOnMissingBean(name = "primaryChatModel")
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.chat", name = "mode", havingValue = "dynamic-priority", matchIfMissing = true)
    public ChatModel dynamicPriorityPrimaryChatModel(LlmRuntimeCatalog llmRuntimeCatalog) {
        return llmRuntimeCatalog.resolvePrimaryChatModel(resolveChatPriority())
                .orElseThrow(() -> new IllegalStateException(
                        "No chat runtime binding could be resolved from the available Spring AI ChatModel beans. "
                                + "Configure contexa.llm.selection.chat.priority or provide a ready chat runtime binding."));
    }

    @Bean(name = "primaryChatModel")
    @ConditionalOnMissingBean(name = "primaryChatModel")
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.chat", name = "mode", havingValue = "spring-primary")
    public ChatModel springPrimaryChatModel(LlmRuntimeCatalog llmRuntimeCatalog) {
        return llmRuntimeCatalog.resolveSpringPrimaryChatModel()
                .orElseThrow(() -> new IllegalStateException(
                        "No chat runtime binding is available for spring-primary selection. Register a Spring AI ChatModel bean first."));
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "primaryChatModel")
    public ChatClient primaryChatClient(@Qualifier("primaryChatModel") ChatModel primaryChatModel, AdvisorRegistry advisorRegistry) {
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
            ObjectProvider<ModelSelectionStrategy> modelSelectionStrategyProvider,
            StreamingHandler streamingHandler,
            AdvisorRegistry advisorRegistry,
            @Qualifier("primaryChatClient") ObjectProvider<ChatClient> primaryChatClientProvider) {

        ModelSelectionStrategy modelSelectionStrategy = modelSelectionStrategyProvider.getIfAvailable();
        if (modelSelectionStrategy == null) {
            throw new IllegalStateException(missingChatRuntimeConfigurationMessage());
        }
        if (primaryChatClientProvider.getIfAvailable() == null) {
            throw new IllegalStateException(missingChatRuntimeConfigurationMessage());
        }

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



    @Bean(name = {"primaryEmbeddingModel", "embeddingModel"})
    @Primary
    @ConditionalOnMissingBean(name = {"primaryEmbeddingModel", "embeddingModel"})
    @Conditional(AnyEmbeddingModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.embedding", name = "mode", havingValue = "fixed", matchIfMissing = true)
    public EmbeddingModel fixedPrimaryEmbeddingModel(LlmRuntimeCatalog llmRuntimeCatalog) {
        String provider = resolveFixedEmbeddingProvider();
        return llmRuntimeCatalog.resolvePrimaryEmbeddingModel(provider)
                .orElseThrow(() -> new IllegalStateException(
                        "No embedding runtime binding could be resolved for fixed provider '" + provider + "'. "
                                + "Configure exactly one contexa.llm.selection.embedding.priority value and the matching Spring AI embedding runtime."));
    }

    @Bean(name = {"primaryEmbeddingModel", "embeddingModel"})
    @Primary
    @ConditionalOnMissingBean(name = {"primaryEmbeddingModel", "embeddingModel"})
    @Conditional(AnyEmbeddingModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.embedding", name = "mode", havingValue = "dynamic-priority")
    public EmbeddingModel dynamicPriorityPrimaryEmbeddingModel(LlmRuntimeCatalog llmRuntimeCatalog) {
        throw new IllegalStateException(
                "Dynamic priority embedding selection is not supported because RAG vectors require a fixed provider and dimension. "
                        + "Configure contexa.llm.selection.embedding.mode=fixed and exactly one contexa.llm.selection.embedding.priority value.");
    }

    @Bean(name = {"primaryEmbeddingModel", "embeddingModel"})
    @ConditionalOnMissingBean(name = {"primaryEmbeddingModel", "embeddingModel"})
    @Conditional(AnyEmbeddingModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.embedding", name = "mode", havingValue = "spring-primary")
    public EmbeddingModel springPrimaryEmbeddingModel(LlmRuntimeCatalog llmRuntimeCatalog) {
        return llmRuntimeCatalog.resolveSpringPrimaryEmbeddingModel()
                .orElseThrow(() -> new IllegalStateException(
                        "No embedding runtime binding is available for spring-primary selection. Register a Spring AI EmbeddingModel bean first."));
    }

    @PostConstruct
    public void init() {
    }



    private String resolveChatPriority() {
        if (StringUtils.hasText(contexaLlmSelectionProperties.getChat().getPriority())) {
            return contexaLlmSelectionProperties.getChat().getPriority().trim();
        }
        return contexaProperties.getLlm().getChatModelPriority();
    }

    private String resolveEmbeddingPriority() {
        if (StringUtils.hasText(contexaLlmSelectionProperties.getEmbedding().getPriority())) {
            return contexaLlmSelectionProperties.getEmbedding().getPriority().trim();
        }
        return contexaProperties.getLlm().getEmbeddingModelPriority();
    }

    private String resolveFixedEmbeddingProvider() {
        List<String> providers = Arrays.stream(resolveEmbeddingPriority().split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (providers.size() != 1) {
            throw new IllegalStateException(
                    "Embedding runtime must be fixed to exactly one provider because pgvector storage is dimension-bound. "
                            + "Configure contexa.llm.selection.embedding.priority=openai or contexa.llm.selection.embedding.priority=ollama.");
        }
        return providers.get(0);
    }



    private String missingChatRuntimeConfigurationMessage() {
        return "No Spring AI ChatModel is configured for CONTEXA. "
                + "Add at least one Spring AI chat provider starter to your application dependencies "
                + "(for example org.springframework.ai:spring-ai-starter-model-openai, "
                + "org.springframework.ai:spring-ai-starter-model-anthropic, or "
                + "org.springframework.ai:spring-ai-starter-model-ollama), "
                + "then configure the matching provider under spring.ai.* "
                + "(for example spring.ai.openai.*, spring.ai.anthropic.*, or spring.ai.ollama.*). "
                + "If the dependency is already present, verify that the corresponding API key or base URL is actually set. "
                + "After a ChatModel bean is available, you may optionally control CONTEXA selection with "
                + "contexa.llm.selection.chat.* and contexa.llm.bindings.chat.*.";
    }
}
