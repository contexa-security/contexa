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

import io.micrometer.observation.ObservationRegistry;
import org.springframework.ai.embedding.BatchingStrategy;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.TokenCountBatchingStrategy;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.observation.VectorStoreObservationConvention;
import org.springframework.ai.vectorstore.pgvector.PgVectorStore;
import org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * O-4: Contexa's vector store, on the dedicated Contexa database. Spring AI's PgVectorStore auto-configuration takes the
 * application's default JdbcTemplate; when the application owns sign-in (HOST_OWNED) that is the application's own
 * database, which then fails to start (no vector extension) or silently receives Contexa's decision records. This
 * store is built the same way from the same {@code spring.ai.vectorstore.pgvector.*} settings, only on
 * {@code contexaJdbcTemplate}, ahead of Spring AI's, which then backs off. A VectorStore the application declares
 * itself is left as it is.
 */
@AutoConfiguration(
        afterName = {
                "io.contexa.autoconfigure.core.CoreDataAutoConfiguration",
                "io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration"
        },
        beforeName = "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration")
@ConditionalOnClass(name = {
        "org.springframework.ai.vectorstore.pgvector.PgVectorStore",
        "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreProperties"
})
@ConditionalOnProperty(name = "spring.ai.vectorstore.type", havingValue = "pgvector", matchIfMissing = true)
@EnableConfigurationProperties(PgVectorStoreProperties.class)
public class ContexaPgVectorStoreAutoConfiguration {

    @Bean(name = "contexaVectorStore")
    @ConditionalOnMissingBean(VectorStore.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate", value = EmbeddingModel.class)
    public PgVectorStore vectorStore(@Qualifier("contexaJdbcTemplate") JdbcTemplate contexaJdbcTemplate,
                                     EmbeddingModel contexaEmbeddingModel,
                                     PgVectorStoreProperties properties,
                                     ObjectProvider<ObservationRegistry> observationRegistry,
                                     ObjectProvider<VectorStoreObservationConvention> customObservationConvention,
                                     ObjectProvider<BatchingStrategy> batchingStrategy) {
        return PgVectorStore.builder(contexaJdbcTemplate, contexaEmbeddingModel)
                .schemaName(properties.getSchemaName())
                .idType(properties.getIdType())
                .vectorTableName(properties.getTableName())
                .vectorTableValidationsEnabled(properties.isSchemaValidation())
                .dimensions(properties.getDimensions())
                .distanceType(properties.getDistanceType())
                .removeExistingVectorStoreTable(properties.isRemoveExistingVectorStoreTable())
                .indexType(properties.getIndexType())
                .initializeSchema(properties.isInitializeSchema())
                .observationRegistry(observationRegistry.getIfUnique(() -> ObservationRegistry.NOOP))
                .customObservationConvention(customObservationConvention.getIfAvailable(() -> null))
                .batchingStrategy(batchingStrategy.getIfAvailable(TokenCountBatchingStrategy::new))
                .maxDocumentBatchSize(properties.getMaxDocumentBatchSize())
                .build();
    }
}
