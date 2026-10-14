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

import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.rag.service.PgVectorPastRecordQuery;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.concurrent.ThreadPoolExecutor;

import static org.assertj.core.api.Assertions.assertThat;
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
            assertThat(context).doesNotHaveBean("behaviorQueryTransformer");
            assertThat(context).doesNotHaveBean("riskQueryTransformer");
            assertThat(context).doesNotHaveBean("policyQueryTransformer");
            assertThat(context).doesNotHaveBean("behaviorAnalysisRagAdvisor");
            assertThat(context).doesNotHaveBean("riskAssessmentRagAdvisor");
            assertThat(context).doesNotHaveBean("policyGenerationRagAdvisor");
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
            ThreadPoolExecutor executor = context.getBean("vectorOperationExecutor", ThreadPoolExecutor.class);
            assertThat(executor.getCorePoolSize()).isEqualTo(16);
            assertThat(executor.getMaximumPoolSize()).isEqualTo(16);
        });
        contextRunner.withPropertyValues("contexa.vectorstore.pgvector.parallel-threads=6").run(context -> {
            ThreadPoolExecutor executor = context.getBean("vectorOperationExecutor", ThreadPoolExecutor.class);
            assertThat(executor.getCorePoolSize()).isEqualTo(6);
            assertThat(executor.getMaximumPoolSize()).isEqualTo(6);
        });
    }

    @Test
    @DisplayName("the metadata index is set up at start only when Spring AI initialises the schema (W2-15)")
    void theMetadataIndexIsSetUpOnlyWhenTheSchemaIsInitialised() {
        contextRunner.withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues("spring.ai.vectorstore.pgvector.initialize-schema=true")
                .run(context -> assertThat(context).hasBean("pgVectorMetadataIndexInitializer"));
        contextRunner.withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues("spring.ai.vectorstore.pgvector.initialize-schema=false")
                .run(context -> assertThat(context).doesNotHaveBean("pgVectorMetadataIndexInitializer"));
    }

    @Test
    @DisplayName("the vector service reads past records by the exact pgvector lookup on the configured table (W3-18)")
    void theVectorServiceReadsPastRecordsByTheExactLookupOnTheConfiguredTable() {
        contextRunner.withBean(VectorStore.class, () -> mock(VectorStore.class))
                .run(context -> {
                    // A store that is not pgvector cannot answer the exact lookup.
                    assertThat(context.getBean(UnifiedVectorService.class).pastRecordQuery())
                            .isInstanceOf(PgVectorPastRecordQuery.class);
                    assertThat(context.getBean(UnifiedVectorService.class).pastRecordQuery().available()).isFalse();
                });
        contextRunner.withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues("spring.ai.vectorstore.pgvector.table-name=not a table")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    @DisplayName("vector services are created when VectorStore is available")
    void vectorServicesAreCreatedWhenVectorStoreIsAvailable() {
        contextRunner
                .withBean(VectorStore.class, () -> mock(VectorStore.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(BehaviorVectorService.class);
                    assertThat(context).hasSingleBean(UnifiedVectorService.class);
                    assertThat(context).hasBean("vectorStoreCacheLayer");
                });
    }
}
