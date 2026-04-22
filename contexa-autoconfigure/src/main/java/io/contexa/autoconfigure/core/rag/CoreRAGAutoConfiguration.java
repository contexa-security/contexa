package io.contexa.autoconfigure.core.rag;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacore.std.operations.DistributedStrategyExecutor;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(CoreAdvisorAutoConfiguration.class)
@ConditionalOnProperty(prefix = "contexa.rag", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ContexaProperties.class, PgVectorStoreProperties.class, ContexaRagProperties.class})
public class CoreRAGAutoConfiguration {

    private final ContexaRagProperties ragProps;

    public CoreRAGAutoConfiguration(ContexaRagProperties ragProps) {
        this.ragProps = ragProps;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VectorStore.class)
    public BehaviorVectorService behaviorVectorService(
            VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics,
            ContexaRagProperties ragProperties) {
        return new BehaviorVectorService(vectorStore, vectorStoreMetrics, ragProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public DistributedStrategyExecutor distributedStrategyExecutor(AIStrategyRegistry strategyRegistry) {
        return new DistributedStrategyExecutor(strategyRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VectorStore.class)
    public VectorStoreCacheLayer vectorStoreCacheLayer(
            VectorStore vectorStore,
            TieredStrategyProperties tieredStrategyProperties) {
        return new VectorStoreCacheLayer(vectorStore, tieredStrategyProperties);
    }

    @Bean(destroyMethod = "shutdown")
    @ConditionalOnMissingBean(name = "vectorOperationExecutor")
    public ExecutorService vectorOperationExecutor() {
        return new ThreadPoolExecutor(
                2,
                8,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000),
                namedThreadFactory("Vector-Operation-"),
                new ThreadPoolExecutor.AbortPolicy());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VectorStore.class)
    public UnifiedVectorService unifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore,
            @Qualifier("vectorOperationExecutor") ExecutorService vectorOperationExecutor) {
        return new UnifiedVectorService(properties, cacheLayer, vectorStore, vectorOperationExecutor);
    }

    private ThreadFactory namedThreadFactory(String prefix) {
        AtomicInteger threadNumber = new AtomicInteger(1);
        return runnable -> {
            Thread thread = new Thread(runnable);
            thread.setName(prefix + threadNumber.getAndIncrement());
            return thread;
        };
    }

    @Bean
    @ConditionalOnMissingBean
    public AICoreOperations aiNativeProcessor(
            AuditLogger auditLogger,
            DistributedLockService distributedLockService,
            DistributedStrategyExecutor distributedStrategyExecutor) {
        return new AINativeProcessor(auditLogger, distributedLockService, distributedStrategyExecutor);
    }

    @Bean
    @Primary
    @ConditionalOnBean(value = VectorStore.class, name = "behaviorQueryTransformer")
    @ConditionalOnMissingBean(name = "behaviorAnalysisRagAdvisor")
    public RetrievalAugmentationAdvisor behaviorAnalysisRagAdvisor(
            VectorStore vectorStore,
            @Qualifier("behaviorQueryTransformer") QueryTransformer behaviorQueryTransformer) {

        String thirtyDaysAgo = LocalDateTime.now()
                .minusDays(ragProps.getBehavior().getLookbackDays())
                .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
                filterBuilder.gte("timestamp", thirtyDaysAgo),
                filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue())).build();

        VectorStoreDocumentRetriever documentRetriever = VectorStoreDocumentRetriever.builder()
                .vectorStore(vectorStore)
                .similarityThreshold(ragProps.getDefaults().getSimilarityThreshold())
                .topK(ragProps.getDefaults().getTopK())
                .filterExpression(filter)
                .build();

        return RetrievalAugmentationAdvisor.builder()
                .documentRetriever(documentRetriever)
                .queryTransformers(behaviorQueryTransformer)
                .build();
    }

    @Bean
    @ConditionalOnBean(value = VectorStore.class, name = "riskQueryTransformer")
    @ConditionalOnMissingBean(name = "riskAssessmentRagAdvisor")
    public RetrievalAugmentationAdvisor riskAssessmentRagAdvisor(
            VectorStore vectorStore,
            @Qualifier("riskQueryTransformer") QueryTransformer riskQueryTransformer) {

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
                filterBuilder.eq("documentType", VectorDocumentType.RISK_ASSESSMENT.getValue()),
                filterBuilder.gte("riskScore", 0.5)).build();

        VectorStoreDocumentRetriever documentRetriever = VectorStoreDocumentRetriever.builder()
                .vectorStore(vectorStore)
                .similarityThreshold(ragProps.getRisk().getSimilarityThreshold())
                .topK(ragProps.getRisk().getTopK())
                .filterExpression(filter)
                .build();

        return RetrievalAugmentationAdvisor.builder()
                .documentRetriever(documentRetriever)
                .queryTransformers(riskQueryTransformer)
                .build();
    }

    @Bean
    @ConditionalOnBean(value = VectorStore.class, name = "policyQueryTransformer")
    @ConditionalOnMissingBean(name = "policyGenerationRagAdvisor")
    public RetrievalAugmentationAdvisor policyGenerationRagAdvisor(
            VectorStore vectorStore,
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
    @ConditionalOnBean(ChatClient.Builder.class)
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
    @ConditionalOnBean(ChatClient.Builder.class)
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
    @ConditionalOnBean(ChatClient.Builder.class)
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
