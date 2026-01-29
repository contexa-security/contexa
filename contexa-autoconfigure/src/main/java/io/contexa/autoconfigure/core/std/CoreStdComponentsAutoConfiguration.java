package io.contexa.autoconfigure.core.std;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.advisor.core.SharedAdvisorContext;
import io.contexa.contexacore.std.advisor.security.SecurityContextAdvisor;
import io.contexa.contexacore.std.components.prompt.BehavioralAnalysisStreamingTemplate;
import io.contexa.contexacore.std.components.prompt.BehavioralAnalysisTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.prompt.RiskAssessmentStreamingTemplate;
import io.contexa.contexacore.std.components.prompt.RiskAssessmentTemplate;
import io.contexa.contexacore.std.components.retriever.BehavioralAnalysisContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacore.std.components.retriever.RiskAssessmentContextRetriever;
import io.contexa.contexacore.std.labs.behavior.BehavioralAnalysisLab;
import io.contexa.contexacore.std.labs.DefaultAILabFactory;
import io.contexa.contexacore.std.labs.risk.RiskAssessmentLab;
import io.contexa.contexacore.std.labs.risk.RiskContextEnricher;
import io.contexa.contexacore.std.llm.core.ExecutionContextFactory;
import io.contexa.contexacore.std.llm.handler.DefaultStreamingHandler;
import io.contexa.contexacore.std.llm.model.provider.AnthropicModelProvider;
import io.contexa.contexacore.std.llm.model.provider.OllamaModelProvider;
import io.contexa.contexacore.std.llm.model.provider.OpenAIModelProvider;
import io.contexa.contexacore.std.llm.strategy.DynamicModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.analyzer.DefaultRequestAnalyzer;
import io.contexa.contexacore.std.pipeline.builder.CustomPipelineStepRegistry;
import io.contexa.contexacore.std.pipeline.builder.DynamicPipelineConfigurationBuilder;
import io.contexa.contexacore.std.pipeline.executor.StreamingUniversalPipelineExecutor;
import io.contexa.contexacore.std.pipeline.executor.UniversalPipelineExecutor;
import io.contexa.contexacore.std.pipeline.step.ContextRetrievalStep;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import io.contexa.contexacore.std.pipeline.step.PostprocessingStep;
import io.contexa.contexacore.std.pipeline.step.PreprocessingStep;
import io.contexa.contexacore.std.pipeline.step.PromptGenerationStep;
import io.contexa.contexacore.std.pipeline.step.ResponseParsingStep;
import io.contexa.contexacore.std.pipeline.step.StreamingLLMExecutionStep;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.contexa.contexacore.std.rag.debug.FilterDebugInterceptor;
import io.contexa.contexacore.std.rag.etl.BehaviorMetadataEnricher;
import io.contexa.contexacore.std.rag.processors.AnomalyScoreRanker;
import io.contexa.contexacore.std.rag.processors.PolicyTemplateProcessor;
import io.contexa.contexacore.std.rag.processors.RiskScoreAggregator;
import io.contexa.contexacore.std.rag.processors.TemporalClusteringProcessor;
import io.contexa.contexacore.std.rag.processors.ThreatCorrelator;
import io.contexa.contexacore.std.strategy.BehavioralAnalysisDiagnosisStrategy;
import io.contexa.contexacore.std.strategy.RiskAssessmentDiagnosisStrategy;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.properties.SecurityMappingProperties;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.repository.ApprovalPolicyRepository;
import io.contexa.contexacore.repository.ApprovalPolicyJpaRepository;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.labs.risk.RiskAssessmentVectorService;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.scheduler.ParallelExecutionMonitor;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.analyzer.RequestAnalyzer;
import io.contexa.contexacore.std.pipeline.executor.PipelineExecutor;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import io.contexa.contexacore.std.rag.etl.BehaviorETLPipeline;
import io.contexa.contexacore.std.strategy.AIStrategy;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import io.contexa.contexacore.std.pipeline.step.PipelineStep;
import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacommon.mcp.tool.ToolResolver;
import io.opentelemetry.api.trace.Tracer;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.List;
import java.util.Optional;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.std", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ContexaProperties.class)
public class CoreStdComponentsAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AdvisorRegistry advisorRegistry() {
        return new AdvisorRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    public SharedAdvisorContext sharedAdvisorContext() {
        return new SharedAdvisorContext();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityContextAdvisor securityContextAdvisor(Tracer tracer) {
        return new SecurityContextAdvisor(tracer);
    }

    @Bean
    @ConditionalOnMissingBean
    public BehavioralAnalysisStreamingTemplate behavioralAnalysisStreamingTemplate() {
        return new BehavioralAnalysisStreamingTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public BehavioralAnalysisTemplate behavioralAnalysisTemplate() {
        return new BehavioralAnalysisTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptGenerator promptGenerator(List<PromptTemplate> promptTemplates) {
        return new PromptGenerator(promptTemplates);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessmentStreamingTemplate riskAssessmentStreamingTemplate() {
        return new RiskAssessmentStreamingTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessmentTemplate riskAssessmentTemplate() {
        return new RiskAssessmentTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public BehavioralAnalysisContextRetriever behavioralAnalysisContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            AuditLogRepository auditLogRepository,
            UserRepository userRepository,
            BehaviorVectorService behaviorVectorService) {
        return new BehavioralAnalysisContextRetriever(vectorStore, contextRetrieverRegistry, auditLogRepository,
                userRepository, behaviorVectorService);
    }

    @Bean
    @Primary
    public ContextRetriever contextRetriever(VectorStore vectorStore) {
        return new ContextRetriever(vectorStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public ContextRetrieverRegistry contextRetrieverRegistry(ContextRetriever defaultRetriever) {
        return new ContextRetrieverRegistry(defaultRetriever);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessmentContextRetriever riskAssessmentContextRetriever(
            VectorStore vectorStore,
            UserRepository userRepository,
            AuditLogRepository auditLogRepository,
            BusinessResourceActionRepository businessResourceActionRepository,
            ContextRetrieverRegistry contextRetrieverRegistry,
            RiskAssessmentVectorService riskAssessmentVectorService) {
        return new RiskAssessmentContextRetriever(vectorStore, userRepository, auditLogRepository,
                businessResourceActionRepository, contextRetrieverRegistry, riskAssessmentVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public BehavioralAnalysisLab behavioralAnalysisLab(
            Tracer tracer,
            AINativeProcessor aiNativeProcessor,
            PipelineOrchestrator pipelineOrchestrator,
            BehavioralAnalysisContextRetriever behavioralAnalysisContextRetriever,
            BehaviorVectorService behaviorVectorService) {
        return new BehavioralAnalysisLab(tracer, aiNativeProcessor, pipelineOrchestrator,
                behavioralAnalysisContextRetriever, behaviorVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultAILabFactory defaultAILabFactory(ApplicationContext applicationContext) {
        return new DefaultAILabFactory(applicationContext);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessmentLab riskAssessmentLab(
            Tracer tracer,
            AINativeProcessor aiNativeProcessor,
            PipelineOrchestrator pipelineOrchestrator,
            RiskContextEnricher riskContextEnricher,
            RiskAssessmentVectorService riskAssessmentVectorService) {
        return new RiskAssessmentLab(tracer, aiNativeProcessor, pipelineOrchestrator, riskContextEnricher,
                riskAssessmentVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskContextEnricher riskContextEnricher(
            RedisTemplate<String, Object> redisTemplate,
            UserRepository userRepository,
            AuditLogRepository auditLogRepository,
            BusinessResourceActionRepository businessResourceActionRepository) {
        return new RiskContextEnricher(redisTemplate, userRepository, auditLogRepository,
                businessResourceActionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public ExecutionContextFactory executionContextFactory(
            TieredLLMProperties tieredLLMProperties,
            SecurityMappingProperties securityMappingProperties) {
        return new ExecutionContextFactory(tieredLLMProperties, securityMappingProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultStreamingHandler defaultStreamingHandler(TieredLLMProperties tieredLLMProperties) {
        return new DefaultStreamingHandler(tieredLLMProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public AnthropicModelProvider anthropicModelProvider() {
        return new AnthropicModelProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    public OllamaModelProvider ollamaModelProvider() {
        return new OllamaModelProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    public OpenAIModelProvider openAIModelProvider() {
        return new OpenAIModelProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    public DynamicModelSelectionStrategy dynamicModelSelectionStrategy(
            DynamicModelRegistry dynamicModelRegistry,
            TieredLLMProperties tieredLLMProperties,
            ChatModel primaryChatModel) {
        return new DynamicModelSelectionStrategy(dynamicModelRegistry, tieredLLMProperties, primaryChatModel);
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultRequestAnalyzer defaultRequestAnalyzer() {
        return new DefaultRequestAnalyzer();
    }

    @Bean
    @ConditionalOnMissingBean
    public CustomPipelineStepRegistry customPipelineStepRegistry() {
        return new CustomPipelineStepRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    public DynamicPipelineConfigurationBuilder dynamicPipelineConfigurationBuilder(
            CustomPipelineStepRegistry customPipelineStepRegistry) {
        return new DynamicPipelineConfigurationBuilder(customPipelineStepRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public StreamingUniversalPipelineExecutor streamingUniversalPipelineExecutor(
            Tracer tracer,
            ContextRetrievalStep contextRetrievalStep,
            PreprocessingStep preprocessingStep,
            PromptGenerationStep promptGenerationStep,
            @Qualifier("llmExecutionStep") LLMExecutionStep llmExecutionStep,
            @Qualifier("pipelineSoarToolExecutionStep") @Autowired(required = false) PipelineStep pipelineStep,
            ResponseParsingStep responseParsingStep,
            PostprocessingStep postprocessingStep,
            StreamingLLMExecutionStep streamingLLMExecutionStep,
            ObjectMapper objectMapper) {
        return new StreamingUniversalPipelineExecutor(tracer, contextRetrievalStep, preprocessingStep,
                promptGenerationStep, llmExecutionStep, pipelineStep, responseParsingStep, postprocessingStep,
                streamingLLMExecutionStep, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public UniversalPipelineExecutor universalPipelineExecutor(
            Tracer tracer,
            ContextRetrievalStep contextRetrievalStep,
            PreprocessingStep preprocessingStep,
            PromptGenerationStep promptGenerationStep,
            @Qualifier("llmExecutionStep") LLMExecutionStep llmExecutionStep,
            @Qualifier("pipelineSoarToolExecutionStep") @Autowired(required = false) PipelineStep pipelineStep,
            ResponseParsingStep responseParsingStep,
            PostprocessingStep postprocessingStep) {
        return new UniversalPipelineExecutor(tracer, contextRetrievalStep, preprocessingStep, promptGenerationStep,
                llmExecutionStep, pipelineStep, responseParsingStep, postprocessingStep);
    }

    @Bean
    @ConditionalOnMissingBean
    public ContextRetrievalStep contextRetrievalStep(ContextRetrieverRegistry contextRetrieverRegistry) {
        return new ContextRetrievalStep(contextRetrieverRegistry);
    }

    @Bean
    @Qualifier("llmExecutionStep")
    public LLMExecutionStep llmExecutionStep(LLMClient llmClient) {
        return new LLMExecutionStep(llmClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public PostprocessingStep postprocessingStep(Optional<List<DomainResponseProcessor>> domainResponseProcessors) {
        return new PostprocessingStep(domainResponseProcessors);
    }

    @Bean
    @ConditionalOnMissingBean
    public PreprocessingStep preprocessingStep() {
        return new PreprocessingStep();
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptGenerationStep promptGenerationStep(
            PromptGenerator promptGenerator,
            @Autowired(required = false) ToolResolver toolResolver) {
        return new PromptGenerationStep(promptGenerator, toolResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResponseParsingStep responseParsingStep() {
        return new ResponseParsingStep();
    }

    @Bean
    @ConditionalOnMissingBean
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
    public FilterDebugInterceptor filterDebugInterceptor() {
        return new FilterDebugInterceptor();
    }

    @Bean
    @ConditionalOnMissingBean
    public BehaviorMetadataEnricher behaviorMetadataEnricher() {
        return new BehaviorMetadataEnricher();
    }

    @Bean
    @ConditionalOnMissingBean
    public AnomalyScoreRanker anomalyScoreRanker() {
        return new AnomalyScoreRanker();
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyTemplateProcessor policyTemplateProcessor() {
        return new PolicyTemplateProcessor();
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskScoreAggregator riskScoreAggregator() {
        return new RiskScoreAggregator();
    }

    @Bean
    @ConditionalOnMissingBean
    public TemporalClusteringProcessor temporalClusteringProcessor() {
        return new TemporalClusteringProcessor();
    }

    @Bean
    @ConditionalOnMissingBean
    public ThreatCorrelator threatCorrelator() {
        return new ThreatCorrelator();
    }

    @Bean
    @ConditionalOnMissingBean
    public BehavioralAnalysisDiagnosisStrategy behavioralAnalysisDiagnosisStrategy(AILabFactory aiLabFactory) {
        return new BehavioralAnalysisDiagnosisStrategy(aiLabFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessmentDiagnosisStrategy riskAssessmentDiagnosisStrategy(AILabFactory aiLabFactory) {
        return new RiskAssessmentDiagnosisStrategy(aiLabFactory);
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
    public DynamicModelRegistry dynamicModelRegistry(
            ApplicationContext applicationContext,
            TieredLLMProperties tieredLLMProperties) {
        return new DynamicModelRegistry(applicationContext, tieredLLMProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public PipelineOrchestrator pipelineOrchestrator(
            List<PipelineExecutor> executors,
            RequestAnalyzer requestAnalyzer,
            List<AIStrategy<?, ?>> strategies) {
        return new PipelineOrchestrator(executors, requestAnalyzer, strategies);
    }

    @Bean
    @ConditionalOnMissingBean
    public BehaviorETLPipeline behaviorETLPipeline(
            VectorStore vectorStore,
            JdbcTemplate jdbcTemplate,
            BehaviorMetadataEnricher metadataEnricher) {
        return new BehaviorETLPipeline(vectorStore, jdbcTemplate, metadataEnricher);
    }

    @Bean
    @ConditionalOnMissingBean
    public ParallelExecutionMonitor parallelExecutionMonitor() {
        return new ParallelExecutionMonitor();
    }

    @Bean
    @ConditionalOnMissingBean
    public ApprovalPolicyRepository approvalPolicyRepository(
            ApprovalPolicyJpaRepository jpaRepository) {
        return new ApprovalPolicyRepository(jpaRepository);
    }
}
