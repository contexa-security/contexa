package io.contexa.autoconfigure.core.std;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.llm.runtime.SpringLlmRuntimeCatalog;
import io.contexa.autoconfigure.properties.ContexaLlmBindingProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionResponseProcessor;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.ContexaAdvisorProperties;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.repository.ApprovalPolicyJpaRepository;
import io.contexa.contexacore.repository.ApprovalPolicyRepository;
import io.contexa.contexacore.security.async.AsyncSecurityContextProvider;
import io.contexa.contexacore.std.advisor.security.SecurityContextAdvisor;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.components.prompt.LLMViewComposer;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.prompt.SafePromptNormalizationLLMViewComposer;
import io.contexa.contexacore.std.components.retriever.AuthorizedContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacore.std.labs.DefaultAILabFactory;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.handler.DefaultStreamingHandler;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.strategy.DynamicModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.executor.PipelineExecutor;
import io.contexa.contexacore.std.pipeline.executor.StreamingUniversalPipelineExecutor;
import io.contexa.contexacore.std.pipeline.executor.UniversalPipelineExecutor;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import io.contexa.contexacore.std.pipeline.step.*;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.rag.service.VectorOperations;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import io.contexa.contexacore.std.strategy.AIStrategy;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@AutoConfiguration
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration",
        "org.springframework.ai.model.ollama.autoconfigure.OllamaChatAutoConfiguration",
        "org.springframework.ai.model.openai.autoconfigure.OpenAiChatAutoConfiguration",
        "org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration"
})
@ConditionalOnProperty(prefix = "contexa.std", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ContexaProperties.class, ContexaLlmBindingProperties.class, StreamingProperties.class, ContexaAdvisorProperties.class})
public class CoreStdComponentsAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecurityContextAdvisor securityContextAdvisor(ContexaAdvisorProperties contexaAdvisorProperties, AsyncSecurityContextProvider asyncSecurityContextProvider) {
        return new SecurityContextAdvisor(asyncSecurityContextProvider, contexaAdvisorProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public LLMViewComposer llmViewComposer(TieredStrategyProperties tieredStrategyProperties) {
        return new SafePromptNormalizationLLMViewComposer(
                tieredStrategyProperties.getPromptCompression().isEnabled());
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptGenerator promptGenerator(
            List<PromptTemplate> promptTemplates,
            LLMViewComposer llmViewComposer,
            TieredStrategyProperties tieredStrategyProperties) {
        return new PromptGenerator(promptTemplates, llmViewComposer, tieredStrategyProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry() {
        return StructuredOutputCapabilityRegistry.defaultRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptContextAuthorizationService promptContextAuthorizationService() {
        return new PromptContextAuthorizationService();
    }

        @Bean
    @Primary
    public ContextRetriever contextRetriever(
            ObjectProvider<UnifiedVectorService> unifiedVectorServiceProvider,
            ContexaRagProperties ragProperties,
            PromptContextAuthorizationService promptContextAuthorizationService) {
        VectorOperations vectorOperations = unifiedVectorServiceProvider.getIfAvailable();
        if (vectorOperations == null) {
            vectorOperations = new VectorOperations() {
                @Override
                public void storeDocument(Document document) {
                }

                @Override
                public void storeDocuments(List<Document> documents) {
                }

                @Override
                public List<Document> searchSimilar(String query) {
                    return List.of();
                }

                @Override
                public List<Document> searchSimilar(String query, Map<String, Object> filters) {
                    return List.of();
                }

                @Override
                public List<Document> searchSimilar(SearchRequest request) {
                    return List.of();
                }

                @Override
                public void deleteDocuments(List<String> documentIds) {
                }
            };
        }
        return new AuthorizedContextRetriever(vectorOperations, ragProperties, promptContextAuthorizationService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ContextRetrieverRegistry contextRetrieverRegistry(ContextRetriever defaultRetriever) {
        return new ContextRetrieverRegistry(defaultRetriever);
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultAILabFactory defaultAILabFactory(ApplicationContext applicationContext) {
        return new DefaultAILabFactory(applicationContext);
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultStreamingHandler defaultStreamingHandler(
            TieredLLMProperties tieredLLMProperties,
            JsonStreamingProcessor jsonStreamingProcessor) {
        return new DefaultStreamingHandler(tieredLLMProperties, jsonStreamingProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ChatModel.class)
    public DynamicModelSelectionStrategy dynamicModelSelectionStrategy(
            DynamicModelRegistry dynamicModelRegistry,
            TieredLLMProperties tieredLLMProperties,
            ChatModel primaryChatModel) {
        return new DynamicModelSelectionStrategy(dynamicModelRegistry, tieredLLMProperties, primaryChatModel);
    }

    @Bean
    @ConditionalOnMissingBean
    public StreamingUniversalPipelineExecutor streamingUniversalPipelineExecutor(
            ContextRetrievalStep contextRetrievalStep,
            PreprocessingStep preprocessingStep,
            PromptGenerationStep promptGenerationStep,
            @Qualifier("llmExecutionStep") LLMExecutionStep llmExecutionStep,
            @Qualifier("pipelineSoarToolExecutionStep") @Autowired(required = false) PipelineStep pipelineStep,
            ResponseParsingStep responseParsingStep,
            PostprocessingStep postprocessingStep,
            StreamingLLMExecutionStep streamingLLMExecutionStep,
            ObjectMapper objectMapper) {
        return new StreamingUniversalPipelineExecutor(contextRetrievalStep, preprocessingStep,
                promptGenerationStep, llmExecutionStep, pipelineStep, responseParsingStep, postprocessingStep,
                streamingLLMExecutionStep, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(name = "universalPipelineExecutor")
    public UniversalPipelineExecutor universalPipelineExecutor(
            ContextRetrievalStep contextRetrievalStep,
            PreprocessingStep preprocessingStep,
            PromptGenerationStep promptGenerationStep,
            @Qualifier("llmExecutionStep") LLMExecutionStep llmExecutionStep,
            @Qualifier("pipelineSoarToolExecutionStep") @Autowired(required = false) PipelineStep pipelineStep,
            ResponseParsingStep responseParsingStep,
            PostprocessingStep postprocessingStep) {
        return new UniversalPipelineExecutor(contextRetrievalStep, preprocessingStep, promptGenerationStep,
                llmExecutionStep, pipelineStep, responseParsingStep, postprocessingStep);
    }

    @Bean
    @ConditionalOnBean(ContextRetrieverRegistry.class)
    @ConditionalOnMissingBean
    public ContextRetrievalStep contextRetrievalStep(ContextRetrieverRegistry contextRetrieverRegistry) {
        return new ContextRetrievalStep(contextRetrieverRegistry);
    }

    @Bean
    @Qualifier("llmExecutionStep")
    @ConditionalOnBean(UnifiedLLMOrchestrator.class)
    public LLMExecutionStep llmExecutionStep(
            UnifiedLLMOrchestrator unifiedLLMOrchestrator,
            StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry) {
        return new LLMExecutionStep(unifiedLLMOrchestrator, structuredOutputCapabilityRegistry);
    }
    @Bean
    @ConditionalOnMissingBean
    public PostprocessingStep postprocessingStep(Optional<List<DomainResponseProcessor>> domainResponseProcessors) {
        return new PostprocessingStep(domainResponseProcessors);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityDecisionResponseProcessor securityDecisionResponseProcessor() {
        return new SecurityDecisionResponseProcessor();
    }

    @Bean
    @ConditionalOnMissingBean
    public PreprocessingStep preprocessingStep() {
        return new PreprocessingStep();
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptGenerationStep promptGenerationStep(PromptGenerator promptGenerator) {
        return new PromptGenerationStep(promptGenerator);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResponseParsingStep responseParsingStep() {
        return new ResponseParsingStep();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ToolCapableLLMClient.class)
    public StreamingLLMExecutionStep streamingLLMExecutionStep(ToolCapableLLMClient toolCapableLLMClient) {
        return new StreamingLLMExecutionStep(toolCapableLLMClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public JsonStreamingProcessor jsonStreamingProcessor() {
        return new JsonStreamingProcessor();
    }

    @Bean
    @ConditionalOnMissingBean
    public AIStrategyRegistry aiStrategyRegistry(List<AIStrategy<?, ?>> allStrategies) {
        return new AIStrategyRegistry(allStrategies);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditLogger auditLogger() {
        return new AuditLogger();
    }

    @Bean
    @ConditionalOnMissingBean
    public LlmRuntimeCatalog llmRuntimeCatalog(
            ApplicationContext applicationContext,
            ContexaProperties contexaProperties,
            ContexaLlmBindingProperties contexaLlmBindingProperties) {
        return new SpringLlmRuntimeCatalog((org.springframework.context.ConfigurableApplicationContext) applicationContext,
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

    @Bean
    @ConditionalOnMissingBean
    public PipelineOrchestrator pipelineOrchestrator(
            List<PipelineExecutor> executors,
            List<AIStrategy<?, ?>> strategies) {
        return new PipelineOrchestrator(executors);
    }

    @Bean
    @ConditionalOnMissingBean
    public ApprovalPolicyRepository approvalPolicyRepository(
            ApprovalPolicyJpaRepository jpaRepository) {
        return new ApprovalPolicyRepository(jpaRepository);
    }
}
