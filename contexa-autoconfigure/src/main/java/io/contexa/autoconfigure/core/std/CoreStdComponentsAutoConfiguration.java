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
package io.contexa.autoconfigure.core.std;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.llm.runtime.SpringLlmRuntimeCatalog;
import io.contexa.autoconfigure.properties.ContexaLlmBindingProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.domain.PromptTemplate;
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
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.handler.DefaultStreamingHandler;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.strategy.DynamicModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.executor.PipelineExecutor;
import io.contexa.contexacore.std.pipeline.executor.StreamingUniversalPipelineExecutor;
import io.contexa.contexacore.std.pipeline.executor.UniversalPipelineExecutor;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionResponseProcessor;
import io.contexa.contexacore.std.pipeline.step.*;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.rag.service.VectorOperations;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import io.contexa.contexacore.std.strategy.AIStrategy;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;

@AutoConfiguration
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration",
        "org.springframework.ai.model.ollama.autoconfigure.OllamaChatAutoConfiguration",
        "org.springframework.ai.model.openai.autoconfigure.OpenAiChatAutoConfiguration",
        "org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration"
})
@ConditionalOnProperty(prefix = "contexa.std", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({
        ContexaProperties.class,
        ContexaLlmBindingProperties.class,
        StreamingProperties.class,
        ContexaAdvisorProperties.class,
        TieredLLMProperties.class,
        TieredStrategyProperties.class,
        ContexaRagProperties.class
})
public class CoreStdComponentsAutoConfiguration {

    @Bean(name = "contexaSecurityContextAdvisor")
    @ConditionalOnMissingBean
    public SecurityContextAdvisor securityContextAdvisor(ContexaAdvisorProperties contexaAdvisorProperties, AsyncSecurityContextProvider contexaAsyncSecurityContextProvider) {
        return new SecurityContextAdvisor(contexaAsyncSecurityContextProvider, contexaAdvisorProperties);
    }

    @Bean(name = "contexaLlmViewComposer")
    @ConditionalOnMissingBean
    public LLMViewComposer llmViewComposer() {
        return new SafePromptNormalizationLLMViewComposer();
    }

    @Bean(name = "contexaPromptGenerator")
    @ConditionalOnMissingBean
    public PromptGenerator promptGenerator(
            List<PromptTemplate> promptTemplates,
            LLMViewComposer contexaLlmViewComposer,
            TieredStrategyProperties tieredStrategyProperties) {
        return new PromptGenerator(promptTemplates, contexaLlmViewComposer, tieredStrategyProperties);
    }

    @Bean(name = "contexaStructuredOutputCapabilityRegistry")
    @ConditionalOnMissingBean
    public StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry() {
        return StructuredOutputCapabilityRegistry.defaultRegistry();
    }

    @Bean(name = "contexaPromptContextAuthorizationService")
    @ConditionalOnMissingBean
    public PromptContextAuthorizationService promptContextAuthorizationService() {
        return new PromptContextAuthorizationService();
    }

        @Bean(name = "contexaContextRetriever")
    @Primary
    public ContextRetriever contextRetriever(
            ObjectProvider<UnifiedVectorService> unifiedVectorServiceProvider,
            ContexaRagProperties ragProperties,
            PromptContextAuthorizationService contexaPromptContextAuthorizationService) {
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
        return new AuthorizedContextRetriever(vectorOperations, ragProperties, contexaPromptContextAuthorizationService);
    }

    @Bean(name = "contexaContextRetrieverRegistry")
    @ConditionalOnMissingBean
    public ContextRetrieverRegistry contextRetrieverRegistry(ContextRetriever defaultRetriever) {
        return new ContextRetrieverRegistry(defaultRetriever);
    }

    @Bean(name = "contexaDefaultAILabFactory")
    @ConditionalOnMissingBean
    public DefaultAILabFactory defaultAILabFactory(ApplicationContext applicationContext) {
        return new DefaultAILabFactory(applicationContext);
    }

    @Bean(name = "contexaDefaultStreamingHandler")
    @ConditionalOnMissingBean
    public DefaultStreamingHandler defaultStreamingHandler(
            TieredLLMProperties tieredLLMProperties,
            JsonStreamingProcessor contexaJsonStreamingProcessor) {
        return new DefaultStreamingHandler(tieredLLMProperties, contexaJsonStreamingProcessor);
    }

    @Bean(name = "contexaDynamicModelSelectionStrategy")
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "contexaPrimaryChatModel")
    public DynamicModelSelectionStrategy dynamicModelSelectionStrategy(
            DynamicModelRegistry contexaDynamicModelRegistry,
            TieredLLMProperties tieredLLMProperties,
            @Qualifier("contexaPrimaryChatModel") ChatModel contexaPrimaryChatModel) {
        return new DynamicModelSelectionStrategy(contexaDynamicModelRegistry, tieredLLMProperties, contexaPrimaryChatModel);
    }

    @Bean(name = "contexaStreamingUniversalPipelineExecutor")
    @ConditionalOnMissingBean
    @ConditionalOnBean({LLMClient.class, ToolCapableLLMClient.class})
    public StreamingUniversalPipelineExecutor streamingUniversalPipelineExecutor(
            ContextRetrievalStep contexaContextRetrievalStep,
            PreprocessingStep contexaPreprocessingStep,
            PromptGenerationStep contexaPromptGenerationStep,
            @Qualifier("contexaLlmExecutionStep") LLMExecutionStep contexaLlmExecutionStep,
            @Qualifier("contexaPipelineSoarToolExecutionStep") @Autowired(required = false) PipelineStep pipelineStep,
            ResponseParsingStep contexaResponseParsingStep,
            PostprocessingStep contexaPostprocessingStep,
            StreamingLLMExecutionStep contexaStreamingLLMExecutionStep,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new StreamingUniversalPipelineExecutor(contexaContextRetrievalStep, contexaPreprocessingStep,
                contexaPromptGenerationStep, contexaLlmExecutionStep, pipelineStep, contexaResponseParsingStep, contexaPostprocessingStep,
                contexaStreamingLLMExecutionStep, objectMapper);
    }

    @Bean(name = "contexaUniversalPipelineExecutor")
    @ConditionalOnMissingBean(name = "contexaUniversalPipelineExecutor")
    @ConditionalOnBean(LLMClient.class)
    public UniversalPipelineExecutor universalPipelineExecutor(
            ContextRetrievalStep contexaContextRetrievalStep,
            PreprocessingStep contexaPreprocessingStep,
            PromptGenerationStep contexaPromptGenerationStep,
            @Qualifier("contexaLlmExecutionStep") LLMExecutionStep contexaLlmExecutionStep,
            @Qualifier("contexaPipelineSoarToolExecutionStep") @Autowired(required = false) PipelineStep pipelineStep,
            ResponseParsingStep contexaResponseParsingStep,
            PostprocessingStep contexaPostprocessingStep) {
        return new UniversalPipelineExecutor(contexaContextRetrievalStep, contexaPreprocessingStep, contexaPromptGenerationStep,
                contexaLlmExecutionStep, pipelineStep, contexaResponseParsingStep, contexaPostprocessingStep);
    }

    @Bean(name = "contexaContextRetrievalStep")
    @ConditionalOnBean(ContextRetrieverRegistry.class)
    @ConditionalOnMissingBean
    public ContextRetrievalStep contextRetrievalStep(ContextRetrieverRegistry contexaContextRetrieverRegistry) {
        return new ContextRetrievalStep(contexaContextRetrieverRegistry);
    }

    @Bean(name = "contexaLlmExecutionStep")
    @Qualifier("contexaLlmExecutionStep")
    @ConditionalOnBean(LLMClient.class)
    public LLMExecutionStep llmExecutionStep(
            LLMClient contexaLlmClient,
            StructuredOutputCapabilityRegistry contexaStructuredOutputCapabilityRegistry) {
        return new LLMExecutionStep(contexaLlmClient, contexaStructuredOutputCapabilityRegistry);
    }
    @Bean(name = "contexaPostprocessingStep")
    @ConditionalOnMissingBean
    public PostprocessingStep postprocessingStep(Optional<List<DomainResponseProcessor>> domainResponseProcessors) {
        return new PostprocessingStep(domainResponseProcessors);
    }

    @Bean(name = "contexaSecurityDecisionResponseProcessor")
    @ConditionalOnMissingBean
    public SecurityDecisionResponseProcessor securityDecisionResponseProcessor() {
        return new SecurityDecisionResponseProcessor();
    }

    @Bean(name = "contexaPreprocessingStep")
    @ConditionalOnMissingBean
    public PreprocessingStep preprocessingStep() {
        return new PreprocessingStep();
    }

    @Bean(name = "contexaPromptGenerationStep")
    @ConditionalOnMissingBean
    public PromptGenerationStep promptGenerationStep(PromptGenerator contexaPromptGenerator) {
        return new PromptGenerationStep(contexaPromptGenerator);
    }

    @Bean(name = "contexaResponseParsingStep")
    @ConditionalOnMissingBean
    public ResponseParsingStep responseParsingStep() {
        return new ResponseParsingStep();
    }

    @Bean(name = "contexaStreamingLLMExecutionStep")
    @ConditionalOnMissingBean
    @ConditionalOnBean(ToolCapableLLMClient.class)
    public StreamingLLMExecutionStep streamingLLMExecutionStep(ToolCapableLLMClient contexaToolCapableLLMClient) {
        return new StreamingLLMExecutionStep(contexaToolCapableLLMClient);
    }

    @Bean(name = "contexaJsonStreamingProcessor")
    @ConditionalOnMissingBean
    public JsonStreamingProcessor jsonStreamingProcessor() {
        return new JsonStreamingProcessor();
    }

    @Bean(name = "contexaAiStrategyRegistry")
    @ConditionalOnMissingBean
    public AIStrategyRegistry aiStrategyRegistry(List<AIStrategy<?, ?>> allStrategies) {
        return new AIStrategyRegistry(allStrategies);
    }

    @Bean(name = "contexaAuditLogger")
    @ConditionalOnMissingBean
    public AuditLogger auditLogger() {
        return new AuditLogger();
    }

    @Bean(name = "contexaLlmRuntimeCatalog")
    @ConditionalOnMissingBean
    public LlmRuntimeCatalog llmRuntimeCatalog(
            ApplicationContext applicationContext,
            ContexaProperties contexaProperties,
            ContexaLlmBindingProperties contexaLlmBindingProperties) {
        return new SpringLlmRuntimeCatalog((ConfigurableApplicationContext) applicationContext,
                contexaProperties, contexaLlmBindingProperties);
    }

    @Bean(name = "contexaDynamicModelRegistry")
    @ConditionalOnMissingBean
    public DynamicModelRegistry dynamicModelRegistry(
            ApplicationContext applicationContext,
            TieredLLMProperties tieredLLMProperties,
            LlmRuntimeCatalog contexaLlmRuntimeCatalog) {
        return new DynamicModelRegistry(applicationContext, tieredLLMProperties, contexaLlmRuntimeCatalog);
    }

    @Bean(name = "contexaPipelineOrchestrator")
    @ConditionalOnMissingBean
    public PipelineOrchestrator pipelineOrchestrator(
            List<PipelineExecutor> executors,
            List<AIStrategy<?, ?>> strategies) {
        return new PipelineOrchestrator(executors);
    }

    @Bean(name = "contexaApprovalPolicyRepository")
    @ConditionalOnMissingBean
    public ApprovalPolicyRepository approvalPolicyRepository(
            ApprovalPolicyJpaRepository jpaRepository) {
        return new ApprovalPolicyRepository(jpaRepository);
    }
}


