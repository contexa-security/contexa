/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.core.llm;

import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.autoconfigure.properties.ContexaLlmBindingProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.autoconfigure.core.llm.runtime.SpringLlmRuntimeCatalog;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.handler.DefaultStreamingHandler;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.strategy.DynamicModelSelectionStrategy;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.micrometer.observation.ObservationRegistry;
import jakarta.annotation.PostConstruct;
import java.util.Arrays;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.observation.EmbeddingModelObservationConvention;
import org.springframework.ai.ollama.api.OllamaApi;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.ai.ollama.api.OllamaEmbeddingOptions;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.OllamaEmbeddingModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.util.StringUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

@Slf4j
@Configuration
@RequiredArgsConstructor
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration",
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
@ConditionalOnProperty(prefix = "contexa.llm", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({TieredLLMProperties.class, ContexaLlmSelectionProperties.class, ContexaLlmBindingProperties.class})
public class CoreLLMTieredAutoConfiguration {

    private static final String DEFAULT_OLLAMA_CHAT_MODEL = "qwen3:8b";
    private static final String DEFAULT_OLLAMA_EMBEDDING_MODEL = "mxbai-embed-large";

    @Autowired
    private ContexaProperties contexaProperties;

    @Autowired
    private TieredLLMProperties tieredLLMProperties;

    @Autowired
    private ContexaLlmSelectionProperties contexaLlmSelectionProperties;

    @Bean
    @ConditionalOnMissingBean
    public LlmRuntimeCatalog llmRuntimeCatalog(
            ApplicationContext applicationContext,
            ContexaProperties contexaProperties,
            ContexaLlmBindingProperties contexaLlmBindingProperties) {
        return new SpringLlmRuntimeCatalog((ConfigurableApplicationContext) applicationContext,
                contexaProperties, contexaLlmBindingProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public DynamicModelRegistry dynamicModelRegistry(
            ApplicationContext applicationContext,
            TieredLLMProperties tieredLLMProperties,
            LlmRuntimeCatalog llmRuntimeCatalog) {
        return new DynamicModelRegistry(applicationContext, tieredLLMProperties, llmRuntimeCatalog);
    }

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

    @Bean(name = "primaryChatModel")
    @Primary
    @ConditionalOnMissingBean(name = "primaryChatModel")
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.chat", name = "mode", havingValue = "fixed")
    public ChatModel fixedPrimaryChatModel(LlmRuntimeCatalog llmRuntimeCatalog) {
        String provider = resolveFixedChatProvider();
        return llmRuntimeCatalog.resolvePrimaryChatModel(provider)
                .orElseThrow(() -> new IllegalStateException(
                        "No chat runtime binding could be resolved for fixed provider '" + provider + "'. "
                                + "Configure exactly one contexa.llm.selection.chat.priority value and the matching Spring AI chat runtime."));
    }

    @Bean
    @ConditionalOnMissingBean(ModelSelectionStrategy.class)
    @ConditionalOnBean(name = "primaryChatModel")
    public DynamicModelSelectionStrategy dynamicModelSelectionStrategy(
            DynamicModelRegistry dynamicModelRegistry,
            TieredLLMProperties tieredLLMProperties,
            @Qualifier("primaryChatModel") ChatModel primaryChatModel) {
        return new DynamicModelSelectionStrategy(dynamicModelRegistry, tieredLLMProperties, primaryChatModel);
    }

    @Bean(name = "chatClientBuilder")
    @Primary
    @ConditionalOnMissingBean(name = "chatClientBuilder")
    @ConditionalOnBean(name = "primaryChatModel")
    public ChatClient.Builder contexaPrimaryChatClientBuilder(
            @Qualifier("primaryChatModel") ChatModel primaryChatModel) {
        return ChatClient.builder(primaryChatModel);
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
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnBean(
            value = {ModelSelectionStrategy.class, StreamingHandler.class, AdvisorRegistry.class},
            name = "primaryChatClient"
    )
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
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnBean(UnifiedLLMOrchestrator.class)
    public LLMClient llmClient(UnifiedLLMOrchestrator unifiedLLMOrchestrator) {
        return unifiedLLMOrchestrator;
    }

    @Bean(name = "toolCapableLLMClient")
    @ConditionalOnMissingBean(ToolCapableLLMClient.class)
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnBean(UnifiedLLMOrchestrator.class)
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

    private String resolveFixedChatProvider() {
        List<String> providers = Arrays.stream(resolveChatPriority().split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (providers.size() != 1) {
            throw new IllegalStateException(
                    "Fixed chat runtime selection requires exactly one provider. "
                            + "Configure contexa.llm.selection.chat.priority=openai, anthropic, or ollama.");
        }
        return providers.get(0);
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

    @Configuration
    @ConditionalOnClass(name = "org.springframework.ai.ollama.OllamaChatModel")
    public static class OllamaConfiguration {

        @Bean(name = "contexaOllamaChatApi")
        @ConditionalOnProperty(prefix = "contexa.llm.chat.ollama", name = "base-url")
        @ConditionalOnMissingBean(name = "contexaOllamaChatApi")
        public OllamaApi contexaOllamaChatApi(
                ObjectProvider<RestClient.Builder> restClientBuilderProvider,
                ObjectProvider<WebClient.Builder> webClientBuilderProvider,
                ObjectProvider<ResponseErrorHandler> responseErrorHandlerProvider,
                ContexaProperties contexaProperties) {

            return buildOllamaApi(
                    resolveChatOllamaBaseUrl(contexaProperties),
                    restClientBuilderProvider,
                    webClientBuilderProvider,
                    responseErrorHandlerProvider.getIfAvailable(DefaultResponseErrorHandler::new)
            );
        }

        @Bean(name = "contexaOllamaChatModel")
        @ConditionalOnBean(name = "contexaOllamaChatApi")
        @ConditionalOnMissingBean(name = "contexaOllamaChatModel")
        public OllamaChatModel contexaOllamaChatModel(
                @Qualifier("contexaOllamaChatApi") OllamaApi ollamaApi,
                ContexaProperties contexaProperties) {

            OllamaChatOptions options = OllamaChatOptions.builder().build();
            if (StringUtils.hasText(contexaProperties.getLlm().getChat().getOllama().getModel())) {
                options.setModel(contexaProperties.getLlm().getChat().getOllama().getModel().trim());
            } else {
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

        @Bean(name = "contexaDedicatedEmbeddingOllamaApi")
        @ConditionalOnProperty(prefix = "contexa.llm.embedding.ollama", name = "dedicated-runtime-enabled", havingValue = "true")
        @ConditionalOnMissingBean(name = "contexaDedicatedEmbeddingOllamaApi")
        public OllamaApi contexaDedicatedEmbeddingOllamaApi(
                ObjectProvider<RestClient.Builder> restClientBuilderProvider,
                ObjectProvider<WebClient.Builder> webClientBuilderProvider,
                ObjectProvider<ResponseErrorHandler> responseErrorHandlerProvider,
                ContexaProperties contexaProperties) {

            String baseUrl = resolveDedicatedEmbeddingOllamaBaseUrl(contexaProperties);
            return buildOllamaApi(baseUrl, restClientBuilderProvider, webClientBuilderProvider,
                    responseErrorHandlerProvider.getIfAvailable(DefaultResponseErrorHandler::new));
        }

        @Bean(name = "contexaDedicatedOllamaEmbeddingModel")
        @ConditionalOnProperty(prefix = "contexa.llm.embedding.ollama", name = "dedicated-runtime-enabled", havingValue = "true")
        @ConditionalOnMissingBean(name = "contexaDedicatedOllamaEmbeddingModel")
        public OllamaEmbeddingModel contexaDedicatedOllamaEmbeddingModel(
                @Qualifier("contexaDedicatedEmbeddingOllamaApi") OllamaApi ollamaApi,
                ObjectProvider<ObservationRegistry> observationRegistry,
                ObjectProvider<EmbeddingModelObservationConvention> observationConvention,
                ContexaProperties contexaProperties) {

            return buildOllamaEmbeddingModel(ollamaApi, observationRegistry, observationConvention, resolveEmbeddingModel(contexaProperties));
        }

        @Bean(name = "contexaSharedOllamaEmbeddingModel")
        @ConditionalOnBean(name = "contexaOllamaChatApi")
        @ConditionalOnMissingBean(name = "contexaSharedOllamaEmbeddingModel")
        public OllamaEmbeddingModel contexaSharedOllamaEmbeddingModel(
                @Qualifier("contexaOllamaChatApi") OllamaApi ollamaApi,
                ObjectProvider<ObservationRegistry> observationRegistry,
                ObjectProvider<EmbeddingModelObservationConvention> observationConvention,
                ContexaProperties contexaProperties) {

            return buildOllamaEmbeddingModel(ollamaApi, observationRegistry, observationConvention, resolveEmbeddingModel(contexaProperties));
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

        private String resolveChatOllamaBaseUrl(ContexaProperties contexaProperties) {
            String baseUrl = contexaProperties.getLlm().getChat().getOllama().getBaseUrl();
            if (!StringUtils.hasText(baseUrl)) {
                throw new IllegalStateException("contexa.llm.chat.ollama.base-url must be configured when Ollama chat runtime is enabled");
            }
            return baseUrl.trim();
        }

        private String resolveDedicatedEmbeddingOllamaBaseUrl(ContexaProperties contexaProperties) {
            ContexaProperties.Llm.Embedding.Ollama ollama = contexaProperties.getLlm().getEmbedding().getOllama();
            if (!ollama.isDedicatedRuntimeEnabled()) {
                throw new IllegalStateException("Dedicated embedding runtime requested without contexa.llm.embedding.ollama.dedicated-runtime-enabled=true");
            }
            if (!StringUtils.hasText(ollama.getBaseUrl())) {
                throw new IllegalStateException("contexa.llm.embedding.ollama.base-url must be configured when dedicated embedding runtime is enabled");
            }
            return ollama.getBaseUrl().trim();
        }

        private String resolveEmbeddingModel(ContexaProperties contexaProperties) {
            String configuredModel = contexaProperties.getLlm().getEmbedding().getOllama().getModel();
            if (StringUtils.hasText(configuredModel)) {
                return configuredModel.trim();
            }
            return DEFAULT_OLLAMA_EMBEDDING_MODEL;
        }
    }
}

