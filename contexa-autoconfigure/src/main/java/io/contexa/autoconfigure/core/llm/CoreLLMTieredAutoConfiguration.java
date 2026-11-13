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

import java.time.Duration;
import reactor.netty.http.HttpResources;
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.http.client.HttpClient;
import org.springframework.http.client.ReactorClientHttpRequestFactory;
import org.springframework.http.client.ReactorResourceFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.boot.http.client.ReactorClientHttpRequestFactoryBuilder;
import io.contexa.contexacore.infra.ContexaReactorResources;
import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.autoconfigure.properties.ContexaLlmBindingProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.autoconfigure.core.llm.runtime.SpringLlmRuntimeCatalog;
import io.contexa.autoconfigure.core.llm.runtime.SpringModelServerResolver;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.ModelServerGateProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.ThinkingGenerationAdvisor;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.handler.DefaultStreamingHandler;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.TieredLayerModelVerifier;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.gate.GatedEmbeddingModel;
import io.contexa.contexacore.std.llm.gate.ModelServerGates;
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
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.util.ClassUtils;
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
@EnableConfigurationProperties({TieredLLMProperties.class, ContexaLlmSelectionProperties.class, ContexaLlmBindingProperties.class, SecurityPlaneProperties.class,
        ModelServerGateProperties.class})
public class CoreLLMTieredAutoConfiguration {

    public static final String DEFAULT_OLLAMA_CHAT_MODEL = "qwen3:8b";
    private static final String DEFAULT_OLLAMA_EMBEDDING_MODEL = "mxbai-embed-large";

    @Autowired
    private ContexaProperties contexaProperties;

    @Autowired
    private TieredLLMProperties tieredLLMProperties;

    @Autowired
    private ContexaLlmSelectionProperties contexaLlmSelectionProperties;

    @Autowired
    private SecurityPlaneProperties securityPlaneProperties;

    @Autowired
    private ObjectProvider<ObservationRegistry> observationRegistryProvider;

    @Bean(name = "contexaLlmRuntimeCatalog")
    @ConditionalOnMissingBean
    public LlmRuntimeCatalog llmRuntimeCatalog(
            ApplicationContext applicationContext,
            ContexaProperties contexaProperties,
            ContexaLlmBindingProperties contexaLlmBindingProperties) {
        return new SpringLlmRuntimeCatalog((ConfigurableApplicationContext) applicationContext,
                contexaProperties, contexaLlmBindingProperties);
    }

    /** O-1: which model server a chat or embedding model calls. */
    @Bean(name = "contexaModelServerResolver")
    @ConditionalOnMissingBean
    public SpringModelServerResolver modelServerResolver(Environment environment) {
        return new SpringModelServerResolver(environment);
    }

    /**
     * O-1: one gate per model server that every chat and embedding call passes. A call waits at most until its event's
     * deadline, and without one at most the event budget.
     */
    @Bean(name = "contexaModelServerGates")
    @ConditionalOnMissingBean
    public ModelServerGates modelServerGates(SpringModelServerResolver contexaModelServerResolver,
                                             ModelServerGateProperties modelServerGateProperties) {
        return new ModelServerGates(contexaModelServerResolver, modelServerGateProperties,
                securityPlaneProperties.getAgent().getEventTimeoutMs());
    }

    @Bean(name = "contexaDynamicModelRegistry")
    @ConditionalOnMissingBean
    public DynamicModelRegistry dynamicModelRegistry(
            ApplicationContext applicationContext,
            TieredLLMProperties tieredLLMProperties,
            LlmRuntimeCatalog contexaLlmRuntimeCatalog,
            @Qualifier("contexaPrimaryChatModel") ObjectProvider<ChatModel> primaryChatModel) {
        DynamicModelRegistry registry = new DynamicModelRegistry(applicationContext, tieredLLMProperties,
                contexaLlmRuntimeCatalog);
        // A layer model named in application.yml with no runtime binding runs on a copy of the primary chat model.
        registry.setVariantBase(primaryChatModel::getIfAvailable);
        return registry;
    }

    /** No condition on the primary chat model: this bean is read before that one, and would never be registered. */
    @Bean(name = "contexaTieredLayerModelVerifier")
    @ConditionalOnMissingBean
    public TieredLayerModelVerifier tieredLayerModelVerifier(
            DynamicModelRegistry contexaDynamicModelRegistry,
            TieredLLMProperties tieredLLMProperties,
            @Qualifier("contexaPrimaryChatModel") ObjectProvider<ChatModel> primaryChatModel) {
        return new TieredLayerModelVerifier(contexaDynamicModelRegistry, tieredLLMProperties,
                primaryChatModel::getIfAvailable);
    }

    @Bean(name = "contexaPrimaryChatModel", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaPrimaryChatModel")
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.chat", name = "mode", havingValue = "dynamic-priority", matchIfMissing = true)
    public ChatModel dynamicPriorityPrimaryChatModel(LlmRuntimeCatalog contexaLlmRuntimeCatalog) {
        return contexaLlmRuntimeCatalog.resolvePrimaryChatModel(resolveChatPriority())
                .orElseThrow(() -> new IllegalStateException(
                        "No chat runtime binding could be resolved from the available Spring AI ChatModel beans. "
                                + "Configure contexa.llm.selection.chat.priority or provide a ready chat runtime binding."));
    }

    @Bean(name = "contexaPrimaryChatModel", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaPrimaryChatModel")
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.chat", name = "mode", havingValue = "spring-primary")
    public ChatModel springPrimaryChatModel(LlmRuntimeCatalog contexaLlmRuntimeCatalog) {
        return contexaLlmRuntimeCatalog.resolveSpringPrimaryChatModel()
                .orElseThrow(() -> new IllegalStateException(
                        "No chat runtime binding is available for spring-primary selection. Register a Spring AI ChatModel bean first."));
    }

    @Bean(name = "contexaPrimaryChatModel", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaPrimaryChatModel")
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.chat", name = "mode", havingValue = "fixed")
    public ChatModel fixedPrimaryChatModel(LlmRuntimeCatalog contexaLlmRuntimeCatalog) {
        String provider = resolveFixedChatProvider();
        return contexaLlmRuntimeCatalog.resolveProviderChatModel(provider)
                .orElseThrow(() -> new IllegalStateException(
                        "No chat runtime binding could be resolved for fixed provider '" + provider + "'. "
                                + "Configure exactly one contexa.llm.selection.chat.priority value and the matching Spring AI chat runtime."));
    }

    @Bean(name = "contexaDynamicModelSelectionStrategy")
    @ConditionalOnMissingBean(ModelSelectionStrategy.class)
    @ConditionalOnBean(name = "contexaPrimaryChatModel")
    public DynamicModelSelectionStrategy dynamicModelSelectionStrategy(
            DynamicModelRegistry contexaDynamicModelRegistry,
            TieredLLMProperties tieredLLMProperties,
            @Qualifier("contexaPrimaryChatModel") ChatModel contexaPrimaryChatModel) {
        return new DynamicModelSelectionStrategy(contexaDynamicModelRegistry, tieredLLMProperties, contexaPrimaryChatModel);
    }

    @Bean(name = "contexaChatClientBuilder", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaChatClientBuilder")
    @ConditionalOnBean(name = "contexaPrimaryChatModel")
    public ChatClient.Builder contexaPrimaryChatClientBuilder(
            @Qualifier("contexaPrimaryChatModel") ChatModel contexaPrimaryChatModel) {
        // Spring AI's entity conversion and streamed content read the first generation, where Claude puts its thinking.
        return ChatClient.builder(contexaPrimaryChatModel, observationRegistry(), null, null)
                .defaultAdvisors(ThinkingGenerationAdvisor.INSTANCE);
    }

    @Bean(name = "contexaPrimaryChatClient", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaPrimaryChatClient")
    @ConditionalOnBean(name = "contexaPrimaryChatModel")
    public ChatClient primaryChatClient(@Qualifier("contexaPrimaryChatModel") ChatModel contexaPrimaryChatModel, AdvisorRegistry contexaAdvisorRegistry) {
        ChatClient.Builder builder = ChatClient.builder(contexaPrimaryChatModel, observationRegistry(), null, null)
                .defaultAdvisors(ThinkingGenerationAdvisor.INSTANCE);
        List<Advisor> advisors = contexaAdvisorRegistry.getEnabled();
        if (!advisors.isEmpty()) {
            builder = builder.defaultAdvisors(advisors.toArray(new Advisor[0]));
        }
        return builder.build();
    }

    @Bean(name = "contexaStreamingHandler")
    @ConditionalOnMissingBean(StreamingHandler.class)
    public StreamingHandler streamingHandler(JsonStreamingProcessor contexaJsonStreamingProcessor) {
        return new DefaultStreamingHandler(tieredLLMProperties, contexaJsonStreamingProcessor);
    }

    @Bean(name = "contexaUnifiedLLMOrchestrator")
    @Primary
    @ConditionalOnMissingBean(UnifiedLLMOrchestrator.class)
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnBean(
            value = {ModelSelectionStrategy.class, StreamingHandler.class, AdvisorRegistry.class},
            name = "contexaPrimaryChatClient"
    )
    public UnifiedLLMOrchestrator unifiedLLMOrchestrator(
            ObjectProvider<ModelSelectionStrategy> modelSelectionStrategyProvider,
            StreamingHandler contexaStreamingHandler,
            AdvisorRegistry contexaAdvisorRegistry,
            @Qualifier("contexaPrimaryChatClient") ObjectProvider<ChatClient> primaryChatClientProvider,
            ObjectProvider<ModelServerGates> modelServerGates) {

        ModelSelectionStrategy modelSelectionStrategy = modelSelectionStrategyProvider.getIfAvailable();
        if (modelSelectionStrategy == null) {
            throw new IllegalStateException(missingChatRuntimeConfigurationMessage());
        }
        if (primaryChatClientProvider.getIfAvailable() == null) {
            throw new IllegalStateException(missingChatRuntimeConfigurationMessage());
        }

        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(modelSelectionStrategy, contexaStreamingHandler,
                tieredLLMProperties, contexaAdvisorRegistry, securityPlaneProperties);
        orchestrator.setObservationRegistry(observationRegistry());
        orchestrator.setModelServerGates(modelServerGates.getIfAvailable());
        return orchestrator;
    }

    /** The application's observation registry, or none when it has no single one. */
    private ObservationRegistry observationRegistry() {
        return observationRegistryProvider != null
                ? observationRegistryProvider.getIfUnique(() -> ObservationRegistry.NOOP) : ObservationRegistry.NOOP;
    }

    @Bean(name = "contexaLlmClient")
    @ConditionalOnMissingBean(LLMClient.class)
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnBean(UnifiedLLMOrchestrator.class)
    public LLMClient llmClient(UnifiedLLMOrchestrator contexaUnifiedLLMOrchestrator) {
        return contexaUnifiedLLMOrchestrator;
    }

    @Bean(name = "contexaToolCapableLLMClient")
    @ConditionalOnMissingBean(ToolCapableLLMClient.class)
    @Conditional(AnyChatModelAvailableCondition.class)
    @ConditionalOnBean(UnifiedLLMOrchestrator.class)
    public ToolCapableLLMClient toolCapableLLMClient(UnifiedLLMOrchestrator contexaUnifiedLLMOrchestrator) {
        return contexaUnifiedLLMOrchestrator;
    }

    @Bean(name = {"contexaPrimaryEmbeddingModel", "contexaEmbeddingModel"}, defaultCandidate = false)
    @ConditionalOnMissingBean(name = {"contexaPrimaryEmbeddingModel", "contexaEmbeddingModel"})
    @Conditional(AnyEmbeddingModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.embedding", name = "mode", havingValue = "fixed", matchIfMissing = true)
    public EmbeddingModel fixedPrimaryEmbeddingModel(LlmRuntimeCatalog contexaLlmRuntimeCatalog,
                                                     ObjectProvider<ModelServerGates> modelServerGates) {
        String provider = resolveFixedEmbeddingProvider();
        return contexaLlmRuntimeCatalog.resolvePrimaryEmbeddingModel(provider)
                .map(model -> gated(model, modelServerGates))
                .orElseThrow(() -> new IllegalStateException(
                        "No embedding runtime binding could be resolved for fixed provider '" + provider + "'. "
                                + "Configure exactly one contexa.llm.selection.embedding.priority value and the matching Spring AI embedding runtime."));
    }

    @Bean(name = {"contexaPrimaryEmbeddingModel", "contexaEmbeddingModel"}, defaultCandidate = false)
    @ConditionalOnMissingBean(name = {"contexaPrimaryEmbeddingModel", "contexaEmbeddingModel"})
    @Conditional(AnyEmbeddingModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.embedding", name = "mode", havingValue = "dynamic-priority")
    public EmbeddingModel dynamicPriorityPrimaryEmbeddingModel(LlmRuntimeCatalog contexaLlmRuntimeCatalog) {
        throw new IllegalStateException(
                "Dynamic priority embedding selection is not supported because RAG vectors require a fixed provider and dimension. "
                        + "Configure contexa.llm.selection.embedding.mode=fixed and exactly one contexa.llm.selection.embedding.priority value.");
    }

    @Bean(name = {"contexaPrimaryEmbeddingModel", "contexaEmbeddingModel"}, defaultCandidate = false)
    @ConditionalOnMissingBean(name = {"contexaPrimaryEmbeddingModel", "contexaEmbeddingModel"})
    @Conditional(AnyEmbeddingModelAvailableCondition.class)
    @ConditionalOnProperty(prefix = "contexa.llm.selection.embedding", name = "mode", havingValue = "spring-primary")
    public EmbeddingModel springPrimaryEmbeddingModel(LlmRuntimeCatalog contexaLlmRuntimeCatalog,
                                                      ObjectProvider<ModelServerGates> modelServerGates) {
        return contexaLlmRuntimeCatalog.resolveSpringPrimaryEmbeddingModel()
                .map(model -> gated(model, modelServerGates))
                .orElseThrow(() -> new IllegalStateException(
                        "No embedding runtime binding is available for spring-primary selection. Register a Spring AI EmbeddingModel bean first."));
    }

    @PostConstruct
    public void init() {
    }

    /** O-1: Contexa's vector store embeds through the gate of the embedding model's server. */
    private static EmbeddingModel gated(EmbeddingModel model, ObjectProvider<ModelServerGates> modelServerGates) {
        ModelServerGates gates = modelServerGates.getIfAvailable();
        return gates != null && !(model instanceof GatedEmbeddingModel) ? new GatedEmbeddingModel(model, gates) : model;
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

    /**
     * A model call of Contexa does not wait through the model client's retry for a server that cannot be reached: a
     * stopped model server ends the call in seconds instead of minutes. The retry settings themselves are not changed.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"org.springframework.retry.support.RetryTemplate", "org.springframework.ai.retry.RetryUtils"})
    public static class ModelCallRetryConfiguration {

        @Bean
        public static BeanPostProcessor contexaModelCallRetryListenerRegistrar() {
            return new ModelCallRetryListenerRegistrar();
        }
    }

    @Configuration
    @ConditionalOnClass(name = "org.springframework.ai.ollama.OllamaChatModel")
    public static class OllamaConfiguration implements DisposableBean {

        private ConnectionProvider modelCallConnections;
        private ReactorClientHttpConnector modelCallConnector;

        @Bean(name = "contexaOllamaChatApi", defaultCandidate = false)
        @ConditionalOnProperty(prefix = "contexa.llm.chat.ollama", name = "base-url")
        @ConditionalOnMissingBean(name = "contexaOllamaChatApi")
        public OllamaApi contexaOllamaChatApi(
                ObjectProvider<RestClient.Builder> restClientBuilderProvider,
                ObjectProvider<WebClient.Builder> webClientBuilderProvider,
                ObjectProvider<ResponseErrorHandler> responseErrorHandlerProvider,
                ObjectProvider<ClientHttpRequestFactoryBuilder<?>> requestFactoryBuilderProvider,
                ObjectProvider<ClientHttpRequestFactorySettings> requestFactorySettingsProvider,
                ContexaProperties contexaProperties) {

            return buildOllamaApi(
                    resolveChatOllamaBaseUrl(contexaProperties),
                    modelCallRestClient(restClientBuilderProvider, requestFactoryBuilderProvider, requestFactorySettingsProvider),
                    webClientBuilderProvider,
                    responseErrorHandlerProvider.getIfAvailable(DefaultResponseErrorHandler::new)
            );
        }

        @Bean(name = "contexaOllamaChatModel", defaultCandidate = false)
        @ConditionalOnBean(name = "contexaOllamaChatApi")
        @ConditionalOnMissingBean(name = "contexaOllamaChatModel")
        public OllamaChatModel contexaOllamaChatModel(
                @Qualifier("contexaOllamaChatApi") OllamaApi ollamaApi,
                ContexaProperties contexaProperties,
                ObjectProvider<SpringModelServerResolver> modelServerResolver) {

            OllamaChatOptions options = OllamaChatOptions.builder().build();
            if (StringUtils.hasText(contexaProperties.getLlm().getChat().getOllama().getModel())) {
                options.setModel(contexaProperties.getLlm().getChat().getOllama().getModel().trim());
            } else {
                options.setModel(DEFAULT_OLLAMA_CHAT_MODEL);
            }
            if (StringUtils.hasText(contexaProperties.getLlm().getChat().getOllama().getKeepAlive())) {
                options.setKeepAlive(contexaProperties.getLlm().getChat().getOllama().getKeepAlive().trim());
            }
            OllamaChatModel model = OllamaChatModel.builder()
                    .ollamaApi(ollamaApi)
                    .defaultOptions(options)
                    .build();
            modelServerResolver.ifAvailable(resolver -> resolver.register(model, "ollama",
                    resolveChatOllamaBaseUrl(contexaProperties), options.getModel()));
            return model;
        }

        @Bean(name = "contexaDedicatedEmbeddingOllamaApi", defaultCandidate = false)
        @ConditionalOnProperty(prefix = "contexa.llm.embedding.ollama", name = "dedicated-runtime-enabled", havingValue = "true")
        @ConditionalOnMissingBean(name = "contexaDedicatedEmbeddingOllamaApi")
        public OllamaApi contexaDedicatedEmbeddingOllamaApi(
                ObjectProvider<RestClient.Builder> restClientBuilderProvider,
                ObjectProvider<WebClient.Builder> webClientBuilderProvider,
                ObjectProvider<ResponseErrorHandler> responseErrorHandlerProvider,
                ObjectProvider<ClientHttpRequestFactoryBuilder<?>> requestFactoryBuilderProvider,
                ObjectProvider<ClientHttpRequestFactorySettings> requestFactorySettingsProvider,
                ContexaProperties contexaProperties) {

            String baseUrl = resolveDedicatedEmbeddingOllamaBaseUrl(contexaProperties);
            return buildOllamaApi(baseUrl,
                    modelCallRestClient(restClientBuilderProvider, requestFactoryBuilderProvider, requestFactorySettingsProvider),
                    webClientBuilderProvider, responseErrorHandlerProvider.getIfAvailable(DefaultResponseErrorHandler::new));
        }

        @Bean(name = "contexaDedicatedOllamaEmbeddingModel", defaultCandidate = false)
        @ConditionalOnProperty(prefix = "contexa.llm.embedding.ollama", name = "dedicated-runtime-enabled", havingValue = "true")
        @ConditionalOnMissingBean(name = "contexaDedicatedOllamaEmbeddingModel")
        public OllamaEmbeddingModel contexaDedicatedOllamaEmbeddingModel(
                @Qualifier("contexaDedicatedEmbeddingOllamaApi") OllamaApi ollamaApi,
                ObjectProvider<ObservationRegistry> observationRegistry,
                ObjectProvider<EmbeddingModelObservationConvention> observationConvention,
                ContexaProperties contexaProperties,
                ObjectProvider<SpringModelServerResolver> modelServerResolver) {

            OllamaEmbeddingModel model = buildOllamaEmbeddingModel(ollamaApi, observationRegistry, observationConvention,
                    resolveEmbeddingModel(contexaProperties));
            modelServerResolver.ifAvailable(resolver -> resolver.register(model, "ollama",
                    resolveDedicatedEmbeddingOllamaBaseUrl(contexaProperties), resolveEmbeddingModel(contexaProperties)));
            return model;
        }

        @Bean(name = "contexaSharedOllamaEmbeddingModel", defaultCandidate = false)
        @ConditionalOnBean(name = "contexaOllamaChatApi")
        @ConditionalOnMissingBean(name = "contexaSharedOllamaEmbeddingModel")
        public OllamaEmbeddingModel contexaSharedOllamaEmbeddingModel(
                @Qualifier("contexaOllamaChatApi") OllamaApi ollamaApi,
                ObjectProvider<ObservationRegistry> observationRegistry,
                ObjectProvider<EmbeddingModelObservationConvention> observationConvention,
                ContexaProperties contexaProperties,
                ObjectProvider<SpringModelServerResolver> modelServerResolver) {

            OllamaEmbeddingModel model = buildOllamaEmbeddingModel(ollamaApi, observationRegistry, observationConvention,
                    resolveEmbeddingModel(contexaProperties));
            modelServerResolver.ifAvailable(resolver -> resolver.register(model, "ollama",
                    resolveChatOllamaBaseUrl(contexaProperties), resolveEmbeddingModel(contexaProperties)));
            return model;
        }

        private OllamaApi buildOllamaApi(
                String baseUrl,
                RestClient.Builder restClientBuilder,
                ObjectProvider<WebClient.Builder> webClientBuilderProvider,
                ResponseErrorHandler responseErrorHandler
        ) {
            return OllamaApi.builder()
                    .baseUrl(baseUrl)
                    .restClientBuilder(restClientBuilder)
                    // a copy of the application's builder, with the connector Contexa's model calls need; the application's own builder is left as it is
                    .webClientBuilder(webClientBuilderProvider.getIfAvailable(WebClient::builder).clone()
                            .clientConnector(modelCallConnector()))
                    .responseErrorHandler(responseErrorHandler)
                    .build();
        }

        /**
         * Model calls stream for minutes: a response timeout of three minutes and a pool of 50 connections, for Contexa's calls only,
         * on Contexa's event loop. One for the model clients of the application, closed with it.
         */
        private synchronized ReactorClientHttpConnector modelCallConnector() {
            if (modelCallConnector == null) {
                modelCallConnections = ContexaReactorResources.connections("contexa-ai-pool", 50);
                modelCallConnector = new ReactorClientHttpConnector(ContexaReactorResources.onContexaLoops(
                        HttpClient.create(modelCallConnections).responseTimeout(Duration.ofMinutes(3))));
            }
            return modelCallConnector;
        }

        @Override
        public synchronized void destroy() {
            if (modelCallConnections != null) {
                modelCallConnections.dispose();
            }
        }

        /**
         * The builder of Contexa's model calls that wait for their answer: a copy of the application's, with the request factory
         * Boot makes from the application's settings ({@code spring.http.client.*} and the customizers of the factory builder) on
         * Contexa's event loop when that factory is Reactor Netty's. A factory of another client has no event loop, and the
         * application's builder is used as it is.
         */
        private static RestClient.Builder modelCallRestClient(
                ObjectProvider<RestClient.Builder> restClientBuilderProvider,
                ObjectProvider<ClientHttpRequestFactoryBuilder<?>> requestFactoryBuilderProvider,
                ObjectProvider<ClientHttpRequestFactorySettings> requestFactorySettingsProvider) {
            RestClient.Builder application = restClientBuilderProvider.getIfAvailable();
            if (application == null) {
                return defaultModelCallRestClient();
            }
            ClientHttpRequestFactoryBuilder<?> requestFactories =
                    requestFactoryBuilderProvider.getIfAvailable(ClientHttpRequestFactoryBuilder::detect);
            if (!(requestFactories instanceof ReactorClientHttpRequestFactoryBuilder)) {
                return application;
            }
            return application.clone().requestFactory(ContexaReactorResources.onContexaLoops(requestFactories)
                    .build(requestFactorySettingsProvider.getIfAvailable(ClientHttpRequestFactorySettings::defaults)));
        }

        /**
         * RestClient.builder() as an application without Boot's builder has it: the request factory Spring picks from the class
         * path, and when that is Reactor Netty's, Spring's own client with its defaults on the same connections, on Contexa's
         * event loop.
         */
        private static RestClient.Builder defaultModelCallRestClient() {
            ClassLoader classLoader = RestClient.class.getClassLoader();
            if (ClassUtils.isPresent("org.apache.hc.client5.http.classic.HttpClient", classLoader)
                    || ClassUtils.isPresent("org.eclipse.jetty.client.HttpClient", classLoader)
                    || !ClassUtils.isPresent("reactor.netty.http.client.HttpClient", classLoader)) {
                return RestClient.builder();
            }
            ReactorResourceFactory resources = new ReactorResourceFactory();
            resources.setUseGlobalResources(false);
            resources.setConnectionProvider(HttpResources.get());
            resources.setLoopResources(ContexaReactorResources.eventLoops());
            resources.start();
            return RestClient.builder().requestFactory(new ReactorClientHttpRequestFactory(resources, client -> client));
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

