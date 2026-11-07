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
package io.contexa.autoconfigure.core.rag;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningLossMetrics;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.gate.CallKind;
import io.contexa.contexacore.std.llm.gate.ModelServerGates;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacore.std.operations.DistributedStrategyExecutor;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.properties.VectorStoreRetryProperties;
import io.contexa.contexacore.std.rag.service.BehaviorDocumentRetentionScheduler;
import io.contexa.contexacore.std.rag.service.FailedDocumentSink;
import io.contexa.contexacore.std.rag.service.InMemoryFailedDocumentSink;
import io.contexa.contexacore.std.rag.service.PendingStoreUserPurgeContributor;
import io.contexa.contexacore.std.rag.service.PgVectorMetadataIndex;
import io.contexa.contexacore.std.rag.service.PgVectorSearchSettings;
import io.contexa.contexacore.std.rag.service.PgVectorPastRecordQuery;
import io.contexa.contexacore.std.rag.service.PgVectorVocabularyReindexer;
import io.contexa.contexacore.std.rag.service.StoreFailureMetrics;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration",
        "io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration",
        "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration"
})
@ConditionalOnProperty(prefix = "contexa.rag", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({
        ContexaProperties.class,
        ContexaLlmSelectionProperties.class,
        PgVectorStoreProperties.class,
        VectorStoreRetryProperties.class,
        ContexaRagProperties.class,
        SecurityPlaneProperties.class,
        TieredStrategyProperties.class
})
public class CoreRAGAutoConfiguration {

    private final ContexaRagProperties ragProps;

    public CoreRAGAutoConfiguration(ContexaRagProperties ragProps) {
        this.ragProps = ragProps;
    }

    @Bean(name = "contexaBehaviorVectorService")
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "contexaVectorStore")
    public BehaviorVectorService behaviorVectorService(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics contexaVectorStoreMetrics,
            ContexaRagProperties ragProperties) {
        return new BehaviorVectorService(vectorStore, contexaVectorStoreMetrics, ragProperties);
    }

    @Bean(name = "contexaDistributedStrategyExecutor")
    @ConditionalOnMissingBean
    public DistributedStrategyExecutor distributedStrategyExecutor(AIStrategyRegistry strategyRegistry) {
        return new DistributedStrategyExecutor(strategyRegistry);
    }

    @Bean(name = "contexaBehaviorDocumentRetentionScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "contexaVectorStore")
    public BehaviorDocumentRetentionScheduler behaviorDocumentRetentionScheduler(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            ContexaRagProperties ragProperties,
            ObjectProvider<VectorStoreCacheLayer> vectorStoreCacheLayer) {
        BehaviorDocumentRetentionScheduler scheduler = new BehaviorDocumentRetentionScheduler(vectorStore, ragProperties);
        scheduler.setVectorStoreCacheLayer(vectorStoreCacheLayer.getIfAvailable());
        return scheduler;
    }

    @Bean(name = "contexaVectorStoreCacheLayer")
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "contexaVectorStore")
    public VectorStoreCacheLayer vectorStoreCacheLayer(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            TieredStrategyProperties tieredStrategyProperties,
            PgVectorStoreProperties pgVectorStoreProperties) {
        return new VectorStoreCacheLayer(vectorStore, tieredStrategyProperties,
                new PgVectorSearchSettings(pgVectorStoreProperties));
    }

    /**
     * The metadata index of the pgvector table, created at start when Spring AI initialises the schema (W2-15), so
     * that a personal search reads one user's rows directly. A store that is not pgvector has none.
     */
    @Bean(name = "contexaPgVectorMetadataIndexInitializer")
    @ConditionalOnBean(name = "contexaVectorStore")
    @ConditionalOnProperty(prefix = "contexa.vectorstore.pgvector", name = "initialize-schema", havingValue = "true")
    public SmartInitializingSingleton pgVectorMetadataIndexInitializer(@Qualifier("contexaVectorStore") VectorStore vectorStore, Environment environment) {
        return () -> PgVectorMetadataIndex.ensureFor(vectorStore,
                environment.getProperty("contexa.vectorstore.pgvector.schema-name", "public"),
                environment.getProperty("contexa.vectorstore.pgvector.table-name", "ctxa_vector_store"));
    }

    /**
     * Moves the past-record documents stored under another classification vocabulary into today's once the context
     * is ready (W5-7 D5), on a background thread so that the start does not wait for it. A store that is not
     * pgvector has none to move.
     */
    @Bean(name = "contexaPgVectorVocabularyReindexOnStart")
    @ConditionalOnBean(name = "contexaVectorStore")
    @ConditionalOnProperty(prefix = "contexa.rag", name = "vocabulary-reindex-on-start", havingValue = "true",
            matchIfMissing = true)
    public ApplicationListener<ApplicationReadyEvent> pgVectorVocabularyReindexOnStart(@Qualifier("contexaVectorStore") VectorStore vectorStore,
                                                                                       Environment environment) {
        PgVectorVocabularyReindexer reindexer = new PgVectorVocabularyReindexer(vectorStore,
                environment.getProperty("contexa.vectorstore.pgvector.schema-name", "public"),
                environment.getProperty("contexa.vectorstore.pgvector.table-name", "ctxa_vector_store"));
        return event -> {
            Thread reindex = new Thread(() -> {
                try {
                    reindexer.reindex(500);
                } catch (RuntimeException e) {
                    log.error("Past-record vocabulary reindex failed", e);
                }
            }, "Vocabulary-Reindex");
            reindex.setDaemon(true);
            reindex.start();
        };
    }

    /** Vector searches and stores; all configured threads run before work queues (W2-15). */
    @Bean(name = "contexaVectorOperationExecutor", destroyMethod = "shutdown", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaVectorOperationExecutor")
    public ExecutorService vectorOperationExecutor(PgVectorStoreProperties pgVectorStoreProperties) {
        int threads = Math.max(1, pgVectorStoreProperties.getParallelThreads());
        ThreadPoolExecutor pool = new ThreadPoolExecutor(
                threads,
                threads,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000),
                namedThreadFactory("Vector-Operation-"),
                new ThreadPoolExecutor.AbortPolicy());
        // threads that have nothing to do are given back: the pool grows with the work and shrinks without it
        pool.allowCoreThreadTimeOut(true);
        return pool;
    }

    /**
     * Where the documents whose vector store failed wait for their retry (BR-C4, QF-8): a bounded queue in memory.
     * An adopter whose records must outlive a restart provides its own {@link FailedDocumentSink} bean.
     */
    @Bean(name = "contexaFailedDocumentSink")
    @ConditionalOnMissingBean(FailedDocumentSink.class)
    public FailedDocumentSink failedDocumentSink(VectorStoreRetryProperties retryProperties) {
        return new InMemoryFailedDocumentSink(retryProperties.getQueueSize());
    }

    @Bean(name = "contexaUnifiedVectorService")
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "contexaVectorStore")
    public UnifiedVectorService unifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            @Qualifier("contexaVectorOperationExecutor") ExecutorService contexaVectorOperationExecutor,
            Environment environment,
            VectorStoreRetryProperties retryProperties,
            FailedDocumentSink contexaFailedDocumentSink,
            ObjectProvider<EmbeddingDimensionConsistencyVerifier> embeddingDimensionVerifier) {
        // W3-18: the past records of a v20 prompt are read by an exact lookup of the pgvector table.
        UnifiedVectorService service = new UnifiedVectorService(properties, cacheLayer, vectorStore,
                contexaVectorOperationExecutor,
                new PgVectorPastRecordQuery(vectorStore,
                        environment.getProperty("contexa.vectorstore.pgvector.schema-name", "public"),
                        environment.getProperty("contexa.vectorstore.pgvector.table-name", "ctxa_vector_store")),
                retryProperties, contexaFailedDocumentSink);
        // BR-S2: a stored document names the embedding model as the start-up dimension check resolves it (read at the
        // first store, not at start, so that the check's beans are not created early).
        service.setEmbeddingModelSource(() -> {
            EmbeddingDimensionConsistencyVerifier verifier = embeddingDimensionVerifier.getIfAvailable();
            return verifier != null ? verifier.activeEmbeddingModel() : null;
        });
        return service;
    }

    /**
     * Removes the documents of a deleted account that still wait for a vector store retry when the account is purged
     * (BR-C4), so that a retry does not bring its records back.
     */
    @Bean(name = "contexaPendingStoreUserPurgeContributor")
    @ConditionalOnMissingBean(PendingStoreUserPurgeContributor.class)
    @ConditionalOnBean(name = "contexaVectorStore")
    public PendingStoreUserPurgeContributor pendingStoreUserPurgeContributor(UnifiedVectorService contexaUnifiedVectorService) {
        return new PendingStoreUserPurgeContributor(contexaUnifiedVectorService);
    }

    /**
     * Publishes the stores that failed, were retried or were deferred (BR-C4, QF-25 b) and the learnings that could not
     * be stored (BR-S5, QF-12) to Micrometer, in the registry where Spring AI's vector store observation
     * ({@code db.vector.client.operation}) records the store's add, delete and query operations; only where Micrometer
     * is present. Spring AI's pgvector auto-configuration hands the application's observation registry to the store
     * itself; Contexa keeps {@code spring.ai.vectorstore.observations.log-query-response} at its default (false), so
     * the retrieved records are not written into traces.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(MeterRegistry.class)
    static class VectorStoreFailureMetricsConfiguration {

        /**
         * Binds once every singleton exists, so that the registry does not start the vector service early; without a
         * registry or a vector service nothing is bound.
         */
        @Bean(name = "contexaUnifiedVectorServiceStoreFailureMetrics")
        @ConditionalOnMissingBean(name = "contexaUnifiedVectorServiceStoreFailureMetrics")
        public SmartInitializingSingleton unifiedVectorServiceStoreFailureMetrics(
                ObjectProvider<MeterRegistry> registry, ObjectProvider<UnifiedVectorService> vectorService) {
            return () -> vectorService.ifAvailable(
                    service -> registry.ifAvailable(meters -> new StoreFailureMetrics(service).bindTo(meters)));
        }

        /** BR-S5 (QF-12): the baseline learnings that could not be stored; nothing is bound without either bean. */
        @Bean(name = "contexaBaselineLearningLossMetrics")
        @ConditionalOnMissingBean(name = "contexaBaselineLearningLossMetrics")
        public SmartInitializingSingleton baselineLearningLossMetrics(
                ObjectProvider<MeterRegistry> registry, ObjectProvider<BaselineLearningService> baselineLearningService) {
            return () -> baselineLearningService.ifAvailable(
                    service -> registry.ifAvailable(meters -> new BaselineLearningLossMetrics(service).bindTo(meters)));
        }
    }

    @Bean(name = "contexaEmbeddingDimensionConsistencyVerifier")
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "contexaVectorStore")
    public EmbeddingDimensionConsistencyVerifier embeddingDimensionConsistencyVerifier(
            PgVectorStoreProperties properties,
            ContexaLlmSelectionProperties selectionProperties,
            Environment environment,
            ObjectProvider<LlmRuntimeCatalog> runtimeCatalogProvider,
            @Qualifier("contexaDataSource") ObjectProvider<DataSource> dataSourceProvider) {
        return new EmbeddingDimensionConsistencyVerifier(
                properties,
                selectionProperties,
                environment,
                runtimeCatalogProvider.getIfAvailable(),
                dataSourceProvider.getIfAvailable());
    }

    private ThreadFactory namedThreadFactory(String prefix) {
        AtomicInteger threadNumber = new AtomicInteger(1);
        return runnable -> {
            Thread thread = new Thread(runnable);
            thread.setName(prefix + threadNumber.getAndIncrement());
            return thread;
        };
    }

    @Bean(name = "contexaAiNativeProcessor")
    @ConditionalOnMissingBean
    public AICoreOperations aiNativeProcessor(
            AuditLogger contexaAuditLogger,
            DistributedLockService distributedLockService,
            DistributedStrategyExecutor contexaDistributedStrategyExecutor,
            SecurityPlaneProperties securityPlaneProperties) {
        return new AINativeProcessor(contexaAuditLogger, distributedLockService, contexaDistributedStrategyExecutor,
                securityPlaneProperties.getAgent().getName());
    }

    /**
     * Retrieves the behaviour documents of every user: its filter has no user (BR-S7). It is created only when
     * {@code contexa.rag.behavior.shared-advisor-enabled=true} and is never the primary advisor, so that a host injecting a
     * {@link RetrievalAugmentationAdvisor} by type does not read other users' documents by accident.
     */
    @Bean(name = "contexaBehaviorAnalysisRagAdvisor")
    @ConditionalOnProperty(prefix = "contexa.rag.behavior", name = "shared-advisor-enabled", havingValue = "true")
    @ConditionalOnBean(name = {"contexaVectorStore", "contexaBehaviorQueryTransformer"})
    @ConditionalOnMissingBean(name = "contexaBehaviorAnalysisRagAdvisor")
    public RetrievalAugmentationAdvisor behaviorAnalysisRagAdvisor(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            @Qualifier("contexaBehaviorQueryTransformer") QueryTransformer contexaBehaviorQueryTransformer) {

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
                .queryTransformers(contexaBehaviorQueryTransformer)
                .build();
    }

    @Bean(name = "contexaRiskAssessmentRagAdvisor")
    @ConditionalOnBean(name = {"contexaVectorStore", "contexaRiskQueryTransformer"})
    @ConditionalOnMissingBean(name = "contexaRiskAssessmentRagAdvisor")
    public RetrievalAugmentationAdvisor riskAssessmentRagAdvisor(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            @Qualifier("contexaRiskQueryTransformer") QueryTransformer contexaRiskQueryTransformer) {

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
                .queryTransformers(contexaRiskQueryTransformer)
                .build();
    }

    @Bean(name = "contexaPolicyGenerationRagAdvisor")
    @ConditionalOnBean(name = {"contexaVectorStore", "contexaPolicyQueryTransformer"})
    @ConditionalOnMissingBean(name = "contexaPolicyGenerationRagAdvisor")
    public RetrievalAugmentationAdvisor policyGenerationRagAdvisor(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            @Qualifier("contexaPolicyQueryTransformer") QueryTransformer contexaPolicyQueryTransformer) {

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
                .queryTransformers(contexaPolicyQueryTransformer)
                .build();
    }

    @Bean("contexaBehaviorQueryTransformer")
    @ConditionalOnBean(name = "contexaChatClientBuilder")
    @ConditionalOnMissingBean(name = "contexaBehaviorQueryTransformer")
    public QueryTransformer behaviorQueryTransformer(@Qualifier("contexaChatClientBuilder") ChatClient.Builder contexaChatClientBuilder,
            ObjectProvider<ModelServerGates> modelServerGates,
            @Qualifier("contexaPrimaryChatModel") ObjectProvider<ChatModel> primaryChatModel) {
        return new QueryTransformer() {
            private final ChatClient chatClient = contexaChatClientBuilder.build();

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

                String transformedText = throughModelServerGate(modelServerGates, primaryChatModel,
                        () -> chatClient.prompt()
                                .user(prompt)
                                .call()
                                .content());

                return new Query(transformedText);
            }
        };
    }

    @Bean("contexaRiskQueryTransformer")
    @ConditionalOnBean(name = "contexaChatClientBuilder")
    @ConditionalOnMissingBean(name = "contexaRiskQueryTransformer")
    public QueryTransformer riskQueryTransformer(@Qualifier("contexaChatClientBuilder") ChatClient.Builder contexaChatClientBuilder,
            ObjectProvider<ModelServerGates> modelServerGates,
            @Qualifier("contexaPrimaryChatModel") ObjectProvider<ChatModel> primaryChatModel) {
        return new QueryTransformer() {
            private final ChatClient chatClient = contexaChatClientBuilder.build();

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

                String transformedText = throughModelServerGate(modelServerGates, primaryChatModel,
                        () -> chatClient.prompt()
                                .user(prompt)
                                .call()
                                .content());

                return new Query(transformedText);
            }
        };
    }

    @Bean("contexaPolicyQueryTransformer")
    @ConditionalOnBean(name = "contexaChatClientBuilder")
    @ConditionalOnMissingBean(name = "contexaPolicyQueryTransformer")
    public QueryTransformer policyQueryTransformer(@Qualifier("contexaChatClientBuilder") ChatClient.Builder contexaChatClientBuilder,
            ObjectProvider<ModelServerGates> modelServerGates,
            @Qualifier("contexaPrimaryChatModel") ObjectProvider<ChatModel> primaryChatModel) {
        return new QueryTransformer() {
            private final ChatClient chatClient = contexaChatClientBuilder.build();

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

                String transformedText = throughModelServerGate(modelServerGates, primaryChatModel,
                        () -> chatClient.prompt()
                                .user(prompt)
                                .call()
                                .content());

                return new Query(transformedText);
            }
        };
    }

    /** O-1: a query rewrite is a call of the primary chat model's server and passes its gate. */
    private static String throughModelServerGate(ObjectProvider<ModelServerGates> modelServerGates,
                                                 @Qualifier("contexaPrimaryChatModel") ObjectProvider<ChatModel> primaryChatModel,
                                                 Supplier<String> call) {
        ModelServerGates gates = modelServerGates.getIfAvailable();
        ChatModel model = primaryChatModel.getIfAvailable();
        if (gates == null || model == null) {
            return call.get();
        }
        String modelName = model.getDefaultOptions() != null ? model.getDefaultOptions().getModel() : null;
        try {
            return gates.call(model, CallKind.CHAT, modelName, call::get);
        } catch (RuntimeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }
}
