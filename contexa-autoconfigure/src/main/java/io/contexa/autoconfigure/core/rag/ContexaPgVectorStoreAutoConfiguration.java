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
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * O-4: Contexa's vector store, on the dedicated Contexa database, built from Contexa's own keys
 * ({@code contexa.vectorstore.pgvector.*}). Spring AI's PgVectorStore auto-configuration
 * takes the application's default JdbcTemplate: its store belongs to the application, and Contexa writes nothing under Spring AI's
 * keys, so with Spring AI's defaults it creates nothing in the application's database. Contexa's decision records go only to
 * this store: it is not a default candidate, and Contexa's code names it.
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
public class ContexaPgVectorStoreAutoConfiguration {

    private static final int HNSW_MAX_DIMENSIONS = 2000;

    /**
     * Spring AI's settings type, bound from Contexa's keys. Not a default candidate: Spring AI's auto-configuration takes this type for the application's own
     * store and must find its own bean, bound from its own keys.
     */
    @Bean(name = "contexaVectorStoreSettings", defaultCandidate = false)
    @ConfigurationProperties(prefix = "contexa.vectorstore.pgvector")
    public PgVectorStoreProperties contexaVectorStoreSettings() {
        return new PgVectorStoreProperties();
    }

    // Contexa always has a vector store of its own, in its own database, and it is not the default one: an application with a pgvector starter keeps
    // its own auto-configured VectorStore, and the documents of Contexa never go to the application's store.
    @Bean(name = "contexaVectorStore", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaVectorStore")
    @ConditionalOnBean(name = {"contexaJdbcTemplate", "contexaPrimaryEmbeddingModel"})
    public PgVectorStore vectorStore(@Qualifier("contexaJdbcTemplate") JdbcTemplate contexaJdbcTemplate,
                                     @Qualifier("contexaPrimaryEmbeddingModel") EmbeddingModel contexaEmbeddingModel,
                                     @Qualifier("contexaVectorStoreSettings") PgVectorStoreProperties properties,
                                     ObjectProvider<ObservationRegistry> observationRegistry,
                                     ObjectProvider<VectorStoreObservationConvention> customObservationConvention,
                                     ObjectProvider<BatchingStrategy> batchingStrategy) {
        refuseWhatTheIndexCannotHold(properties);
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

    /** The database would only say that the index failed: what to do about it is said here. */
    private static void refuseWhatTheIndexCannotHold(PgVectorStoreProperties properties) {
        if (properties.isInitializeSchema() && properties.getIndexType() == PgVectorStore.PgIndexType.HNSW
                && properties.getDimensions() > HNSW_MAX_DIMENSIONS) {
            throw new IllegalStateException("""
                    The vector store cannot create its index: an HNSW index holds at most %d dimensions and %d were asked for.
                    Configure a smaller output, for example spring.ai.openai.embedding.options.dimensions=1536 with text-embedding-3-large,
                    or create the table yourself and set contexa.vectorstore.pgvector.initialize-schema=false.
                    """.formatted(HNSW_MAX_DIMENSIONS, properties.getDimensions()).trim());
        }
    }
}
