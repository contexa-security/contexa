package io.contexa.autoconfigure.core.rag;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacore.std.operations.DistributedSessionManager;
import io.contexa.contexacore.std.operations.DistributedStrategyExecutor;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration.class)
@ConditionalOnProperty(prefix = "contexa.rag", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ ContexaProperties.class, PgVectorStoreProperties.class })
public class CoreRAGAutoConfiguration {

    @Value("${spring.ai.rag.similarity-threshold:0.75}")
    private double defaultSimilarityThreshold;

    @Value("${spring.ai.rag.top-k:100}")
    private int defaultTopK;

    @Value("${spring.ai.rag.behavior.lookback-days:30}")
    private int behaviorLookbackDays;

    @Value("${spring.ai.rag.risk.similarity-threshold:0.8}")
    private double riskSimilarityThreshold;

    @Value("${spring.ai.rag.risk.top-k:50}")
    private int riskTopK;

    public CoreRAGAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean
    public DistributedSessionManager distributedSessionManager(
            AuditLogger auditLogger) {
        return new DistributedSessionManager(auditLogger);
    }

    @Bean
    @ConditionalOnMissingBean
    public BehaviorVectorService behaviorVectorService(
            VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new BehaviorVectorService(vectorStore, vectorStoreMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public DistributedStrategyExecutor distributedStrategyExecutor(
            PipelineOrchestrator orchestrator,
            AIStrategyRegistry strategyRegistry) {
        return new DistributedStrategyExecutor(orchestrator, strategyRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public VectorStoreCacheLayer vectorStoreCacheLayer(VectorStore vectorStore) {
        return new VectorStoreCacheLayer(vectorStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public UnifiedVectorService unifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore) {
        return new UnifiedVectorService(properties, cacheLayer, vectorStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public AICoreOperations aiNativeProcessor(
            DistributedSessionManager sessionManager,
            RedisDistributedLockService distributedLockService,
            DistributedStrategyExecutor distributedStrategyExecutor) {
        return new AINativeProcessor(
                sessionManager, distributedLockService, distributedStrategyExecutor);
    }

    @Bean
    @Primary
    @ConditionalOnBean(ChatModel.class)
    @ConditionalOnMissingBean(name = "behaviorAnalysisRagAdvisor")
    public RetrievalAugmentationAdvisor behaviorAnalysisRagAdvisor(
            VectorStore vectorStore,
            ChatClient.Builder chatClientBuilder,
            @Qualifier("behaviorQueryTransformer") QueryTransformer behaviorQueryTransformer) {

        String thirtyDaysAgo = LocalDateTime.now()
                .minusDays(behaviorLookbackDays)
                .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
                filterBuilder.gte("timestamp", thirtyDaysAgo),
                filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue())).build();

        VectorStoreDocumentRetriever documentRetriever = VectorStoreDocumentRetriever.builder()
                .vectorStore(vectorStore)
                .similarityThreshold(defaultSimilarityThreshold)
                .topK(defaultTopK)
                .filterExpression(filter)
                .build();

        return RetrievalAugmentationAdvisor.builder()
                .documentRetriever(documentRetriever)
                .queryTransformers(behaviorQueryTransformer)
                .build();
    }

    @Bean
    @ConditionalOnBean(ChatModel.class)
    @ConditionalOnMissingBean(name = "riskAssessmentRagAdvisor")
    public RetrievalAugmentationAdvisor riskAssessmentRagAdvisor(
            VectorStore vectorStore,
            ChatClient.Builder chatClientBuilder,
            @Qualifier("riskQueryTransformer") QueryTransformer riskQueryTransformer) {

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
                filterBuilder.eq("documentType", VectorDocumentType.RISK_ASSESSMENT.getValue()),
                filterBuilder.gte("riskScore", 0.5)).build();

        VectorStoreDocumentRetriever documentRetriever = VectorStoreDocumentRetriever.builder()
                .vectorStore(vectorStore)
                .similarityThreshold(riskSimilarityThreshold)
                .topK(riskTopK)
                .filterExpression(filter)
                .build();

        return RetrievalAugmentationAdvisor.builder()
                .documentRetriever(documentRetriever)
                .queryTransformers(riskQueryTransformer)
                .build();
    }

    @Bean
    @ConditionalOnBean(ChatModel.class)
    @ConditionalOnMissingBean(name = "policyGenerationRagAdvisor")
    public RetrievalAugmentationAdvisor policyGenerationRagAdvisor(
            VectorStore vectorStore,
            ChatClient.Builder chatClientBuilder,
            @Qualifier("policyQueryTransformer") QueryTransformer policyQueryTransformer) {

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.eq("documentType", VectorDocumentType.POLICY_EVOLUTION.getValue()).build();

        VectorStoreDocumentRetriever documentRetriever = VectorStoreDocumentRetriever.builder()
                .vectorStore(vectorStore)
                .similarityThreshold(0.7)
                .topK(20)
                .filterExpression(filter)
                .build();

        return RetrievalAugmentationAdvisor.builder()
                .documentRetriever(documentRetriever)
                .queryTransformers(policyQueryTransformer)
                .build();
    }

    @Bean("behaviorQueryTransformer")
    @ConditionalOnBean(ChatModel.class)
    @ConditionalOnMissingBean(name = "behaviorQueryTransformer")
    public QueryTransformer behaviorQueryTransformer(ChatClient.Builder chatClientBuilder) {
        return new QueryTransformer() {
            private final ChatClient chatClient = chatClientBuilder.build();

            @Override
            public Query transform(Query originalQuery) {
                if (originalQuery == null || originalQuery.text() == null) {
                    return originalQuery;
                }

                String prompt = """
                        Optimize the following query for user behavior pattern analysis:

                        Original Query: %s

                        Optimization Guidelines:
                        1. Include temporal context (last 30 days)
                        2. Add keywords to search for similar behavior patterns
                        3. Reinforce anomaly-related terms
                        4. Consider user role and permission context

                        Return only the optimized query.
                        """.formatted(originalQuery.text());

                String transformedText = chatClient.prompt()
                        .user(prompt)
                        .call()
                        .content();

                return new Query(transformedText);
            }
        };
    }

    @Bean("riskQueryTransformer")
    @ConditionalOnBean(ChatModel.class)
    @ConditionalOnMissingBean(name = "riskQueryTransformer")
    public QueryTransformer riskQueryTransformer(ChatClient.Builder chatClientBuilder) {
        return new QueryTransformer() {
            private final ChatClient chatClient = chatClientBuilder.build();

            @Override
            public Query transform(Query originalQuery) {
                if (originalQuery == null || originalQuery.text() == null) {
                    return originalQuery;
                }

                String prompt = """
                        Optimize the following query for security risk assessment:

                        Original Query: %s

                        Optimization Guidelines:
                        1. Include Threat Indicators (IOC)
                        2. Expand to search for past incident patterns
                        3. Add classification keywords by risk level
                        4. Include MITRE ATT&CK framework related terms

                        Return only the optimized query.
                        """.formatted(originalQuery.text());

                String transformedText = chatClient.prompt()
                        .user(prompt)
                        .call()
                        .content();

                return new Query(transformedText);
            }
        };
    }

    @Bean("policyQueryTransformer")
    @ConditionalOnBean(ChatModel.class)
    @ConditionalOnMissingBean(name = "policyQueryTransformer")
    public QueryTransformer policyQueryTransformer(ChatClient.Builder chatClientBuilder) {
        return new QueryTransformer() {
            private final ChatClient chatClient = chatClientBuilder.build();

            @Override
            public Query transform(Query originalQuery) {
                if (originalQuery == null || originalQuery.text() == null) {
                    return originalQuery;
                }

                String prompt = """
                        Optimize the following query for policy generation:

                        Original Query: %s

                        Optimization Guidelines:
                        1. Expand to find similar policy templates
                        2. Include Role-Based Access Control (RBAC) related terms
                        3. Consider compliance requirements
                        4. Include business rules and conditions

                        Return only the optimized query.
                        """.formatted(originalQuery.text());

                String transformedText = chatClient.prompt()
                        .user(prompt)
                        .call()
                        .content();

                return new Query(transformedText);
            }
        };
    }
}
