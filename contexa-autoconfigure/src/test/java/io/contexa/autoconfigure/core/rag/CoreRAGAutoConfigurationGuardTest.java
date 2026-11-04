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

import io.contexa.contexacore.autonomous.service.UserStatePurgeContributor;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.rag.properties.VectorStoreRetryProperties;
import io.contexa.contexacore.std.rag.service.FailedDocumentSink;
import io.contexa.contexacore.std.rag.service.InMemoryFailedDocumentSink;
import io.contexa.contexacore.std.rag.service.PendingStoreUserPurgeContributor;
import io.contexa.contexacore.std.rag.service.PgVectorPastRecordQuery;
import io.contexa.contexacore.std.rag.service.StoreFailureStats;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.rag.service.VectorOperations;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ThreadPoolExecutor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

class CoreRAGAutoConfigurationGuardTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreRAGAutoConfiguration.class))
            .withBean(AIStrategyRegistry.class, () -> mock(AIStrategyRegistry.class))
            .withBean(AuditLogger.class, () -> mock(AuditLogger.class))
            .withBean(DistributedLockService.class, () -> mock(DistributedLockService.class));

    @Test
    @DisplayName("rag advisors and vector services back off without ChatClient.Builder and VectorStore")
    void ragBeansBackOffWithoutChatClientBuilderAndVectorStore() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean("contexaBehaviorQueryTransformer");
            assertThat(context).doesNotHaveBean("contexaRiskQueryTransformer");
            assertThat(context).doesNotHaveBean("contexaPolicyQueryTransformer");
            assertThat(context).doesNotHaveBean("contexaBehaviorAnalysisRagAdvisor");
            assertThat(context).doesNotHaveBean("contexaRiskAssessmentRagAdvisor");
            assertThat(context).doesNotHaveBean("contexaPolicyGenerationRagAdvisor");
            assertThat(context).doesNotHaveBean(UnifiedVectorService.class);
        });
    }

    @Test
    @DisplayName("CoreRAGAutoConfiguration runs after embedding/vector-store auto-configuration")
    void coreRagAutoConfigurationRunsAfterVectorStoreAutoConfiguration() {
        AutoConfigureAfter annotation = CoreRAGAutoConfiguration.class.getAnnotation(AutoConfigureAfter.class);

        assertThat(annotation).isNotNull();
        assertThat(annotation.name()).contains(
                "io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration",
                "io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration",
                "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration");
    }

    @Test
    @DisplayName("the vector executor runs the configured number of threads, sixteen by default (W2-15)")
    void theVectorExecutorRunsTheConfiguredNumberOfThreads() {
        contextRunner.run(context -> {
            ThreadPoolExecutor executor = context.getBean("contexaVectorOperationExecutor", ThreadPoolExecutor.class);
            assertThat(executor.getCorePoolSize()).isEqualTo(16);
            assertThat(executor.getMaximumPoolSize()).isEqualTo(16);
        });
        contextRunner.withPropertyValues("contexa.vectorstore.pgvector.parallel-threads=6").run(context -> {
            ThreadPoolExecutor executor = context.getBean("contexaVectorOperationExecutor", ThreadPoolExecutor.class);
            assertThat(executor.getCorePoolSize()).isEqualTo(6);
            assertThat(executor.getMaximumPoolSize()).isEqualTo(6);
        });
    }

    @Test
    @DisplayName("the metadata index is set up at start only when Spring AI initialises the schema (W2-15)")
    void theMetadataIndexIsSetUpOnlyWhenTheSchemaIsInitialised() {
        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues("contexa.vectorstore.pgvector.initialize-schema=true")
                .run(context -> assertThat(context).hasBean("contexaPgVectorMetadataIndexInitializer"));
        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues("contexa.vectorstore.pgvector.initialize-schema=false")
                .run(context -> assertThat(context).doesNotHaveBean("contexaPgVectorMetadataIndexInitializer"));
    }

    @Test
    @DisplayName("the vector service reads past records by the exact pgvector lookup on the configured table (W3-18)")
    void theVectorServiceReadsPastRecordsByTheExactLookupOnTheConfiguredTable() {
        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class))
                .run(context -> {
                    // A store that is not pgvector cannot answer the exact lookup.
                    assertThat(context.getBean(UnifiedVectorService.class).pastRecordQuery())
                            .isInstanceOf(PgVectorPastRecordQuery.class);
                    assertThat(context.getBean(UnifiedVectorService.class).pastRecordQuery().available()).isFalse();
                });
        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues("contexa.vectorstore.pgvector.table-name=not a table")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    @DisplayName("the retry of failed vector stores is on by default, with a bounded in-memory queue (BR-C4)")
    void theStoreRetryIsOnByDefault() {
        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class)).run(context -> {
            VectorStoreRetryProperties retry = context.getBean(VectorStoreRetryProperties.class);
            assertThat(retry.isEnabled()).isTrue();
            assertThat(retry.getQueueSize()).isEqualTo(2000);
            assertThat(retry.getMaxAttempts()).isEqualTo(20);
            assertThat(retry.getMaxAge()).isEqualTo(Duration.ofHours(1));
            assertThat(retry.getInitialDelay()).isEqualTo(Duration.ofSeconds(10));
            assertThat(retry.getMaxDelay()).isEqualTo(Duration.ofMinutes(5));
            assertThat(context.getBean(FailedDocumentSink.class)).isInstanceOf(InMemoryFailedDocumentSink.class);
        });
    }

    @Test
    @DisplayName("contexa.vectorstore.retry.* binds, and a failed store is queued only while the retry is on (BR-C4)")
    void theStoreRetrySettingsBindAndSwitchTheRetry() {
        VectorStore failingStore = mock(VectorStore.class);
        doThrow(new IllegalStateException("Connection refused")).when(failingStore).add(any());

        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> failingStore)
                .withPropertyValues("contexa.vectorstore.retry.queue-size=7", "contexa.vectorstore.retry.max-attempts=3",
                        "contexa.vectorstore.retry.max-age=30m", "contexa.vectorstore.retry.initial-delay=2s",
                        "contexa.vectorstore.retry.max-delay=40s", "contexa.vectorstore.retry.batch-size=5")
                .run(context -> {
                    VectorStoreRetryProperties retry = context.getBean(VectorStoreRetryProperties.class);
                    assertThat(retry.getQueueSize()).isEqualTo(7);
                    assertThat(retry.getMaxAttempts()).isEqualTo(3);
                    assertThat(retry.getMaxAge()).isEqualTo(Duration.ofMinutes(30));
                    assertThat(retry.getInitialDelay()).isEqualTo(Duration.ofSeconds(2));
                    assertThat(retry.getMaxDelay()).isEqualTo(Duration.ofSeconds(40));
                    assertThat(retry.getBatchSize()).isEqualTo(5);
                    UnifiedVectorService service = context.getBean(UnifiedVectorService.class);
                    assertThatThrownBy(() -> service.storeDocument(new Document("memory", Map.of("eventId", "e-1"))))
                            .hasMessage("Failed to store document");
                    assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(1, 1, 0, 0));
                    assertThat(context.getBean(FailedDocumentSink.class).size()).isEqualTo(1);
                });
        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> failingStore)
                .withPropertyValues("contexa.vectorstore.retry.enabled=false")
                .run(context -> {
                    UnifiedVectorService service = context.getBean(UnifiedVectorService.class);
                    assertThatThrownBy(() -> service.storeDocument(new Document("memory", Map.of("eventId", "e-2"))))
                            .hasMessage("Failed to store document");
                    assertThat(service.storeFailureStats()).isEqualTo(StoreFailureStats.NONE);
                    assertThat(context.getBean(FailedDocumentSink.class).size()).isZero();
                });
    }

    @Test
    @DisplayName("an adopter's own FailedDocumentSink bean holds the waiting documents instead of the in-memory queue")
    void anAdoptersSinkReplacesTheInMemoryQueue() {
        FailedDocumentSink own = new InMemoryFailedDocumentSink(5);
        VectorStore failingStore = mock(VectorStore.class);
        doThrow(new IllegalStateException("Connection refused")).when(failingStore).add(any());

        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> failingStore)
                .withBean(FailedDocumentSink.class, () -> own)
                .run(context -> {
                    assertThat(context.getBean(FailedDocumentSink.class)).isSameAs(own);
                    assertThatThrownBy(() -> context.getBean(UnifiedVectorService.class)
                            .storeDocument(new Document("memory", Map.of("eventId", "e-3"))))
                            .hasMessage("Failed to store document");
                    assertThat(own.size()).isEqualTo(1);
                });
    }

    @Test
    @DisplayName("the stores that failed are published to Micrometer when a registry exists, and nothing breaks without one")
    void theFailedStoresArePublishedToMicrometerWhenARegistryExists() {
        VectorStore failingStore = mock(VectorStore.class);
        doThrow(new IllegalStateException("Connection refused")).when(failingStore).add(any());
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> failingStore)
                .withBean(MeterRegistry.class, () -> registry)
                .run(context -> {
                    assertThatThrownBy(() -> context.getBean(UnifiedVectorService.class)
                            .storeDocument(new Document("memory", Map.of("eventId", "e-4"))))
                            .hasMessage("Failed to store document");
                    assertThat(registry.get("contexa.vector.store.failed").functionCounter().count()).isEqualTo(1.0);
                    assertThat(registry.get("contexa.vector.store.pending").gauge().value()).isEqualTo(1.0);
                });
        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> failingStore)
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    @DisplayName("the account purge also drops the documents of the account that wait for a retry (BR-C4)")
    void thePurgeAlsoDropsTheWaitingDocumentsOfTheAccount() {
        VectorStore failingStore = mock(VectorStore.class);
        doThrow(new IllegalStateException("Connection refused")).when(failingStore).add(any());

        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> failingStore).run(context -> {
            assertThat(context.getBeansOfType(UserStatePurgeContributor.class).values())
                    .extracting(UserStatePurgeContributor::name).contains("pending-vector-stores");
            UnifiedVectorService service = context.getBean(UnifiedVectorService.class);
            assertThatThrownBy(() -> service.storeDocument(new Document("memory", Map.of("eventId", "e-5", "userId", "alice"))))
                    .isInstanceOf(VectorOperations.VectorStoreException.class);
            context.getBean(PendingStoreUserPurgeContributor.class).purge("alice");
            assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(1, 0, 0, 0));
        });
    }

    @Test
    @DisplayName("vector services are created when VectorStore is available")
    void vectorServicesAreCreatedWhenVectorStoreIsAvailable() {
        contextRunner
                .withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(BehaviorVectorService.class);
                    assertThat(context).hasSingleBean(UnifiedVectorService.class);
                    assertThat(context).hasBean("contexaVectorStoreCacheLayer");
                });
    }

    @Test
    @DisplayName("the behaviour advisor that retrieves the documents of every user is not created unless it is asked for (BR-S7)")
    void theUnfilteredBehaviourAdvisorIsOffByDefault() {
        contextRunner
                .withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class))
                .withBean("contexaBehaviorQueryTransformer", QueryTransformer.class, () -> mock(QueryTransformer.class))
                .run(context -> assertThat(context).doesNotHaveBean("contexaBehaviorAnalysisRagAdvisor"));
    }

    @Test
    @DisplayName("asked for, the behaviour advisor exists but is never the primary advisor a host gets by type (BR-S7)")
    void theUnfilteredBehaviourAdvisorIsNeverPrimary() {
        contextRunner
                .withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class))
                .withBean("contexaBehaviorQueryTransformer", QueryTransformer.class, () -> mock(QueryTransformer.class))
                .withPropertyValues("contexa.rag.behavior.shared-advisor-enabled=true")
                .run(context -> {
                    assertThat(context).hasBean("contexaBehaviorAnalysisRagAdvisor");
                    assertThat(context.getBeanFactory().getBeanDefinition("contexaBehaviorAnalysisRagAdvisor").isPrimary()).isFalse();
                });
    }
}
