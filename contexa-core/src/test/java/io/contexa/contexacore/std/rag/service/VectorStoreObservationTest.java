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
package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.properties.VectorStoreRetryProperties;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.observation.DefaultMeterObservationHandler;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.vectorstore.SimpleVectorStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BR-S5: the vector service's stores and searches, run through a store that has the application's observation
 * registry (as Spring AI's pgvector auto-configuration builds it), are observed as {@code db.vector.client.operation}
 * in the same Micrometer registry as the service's {@code contexa.vector.store.*} counters.
 */
class VectorStoreObservationTest {

    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private ExecutorService executor;
    private UnifiedVectorService service;

    @BeforeEach
    void setUp() {
        ObservationRegistry observations = ObservationRegistry.create();
        observations.observationConfig().observationHandler(new DefaultMeterObservationHandler(meters));
        SimpleVectorStore store = SimpleVectorStore.builder(new FixedEmbeddingModel())
                .observationRegistry(observations)
                .build();
        executor = Executors.newFixedThreadPool(2);
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        VectorStoreCacheLayer cacheLayer = new VectorStoreCacheLayer(store, new TieredStrategyProperties(),
                new PgVectorSearchSettings(properties));
        cacheLayer.init();
        service = new UnifiedVectorService(properties, cacheLayer, store, executor, PastRecordQuery.unavailable(),
                new VectorStoreRetryProperties(), null);
        new StoreFailureMetrics(service).bindTo(meters);
    }

    @AfterEach
    void tearDown() throws Exception {
        service.destroy();
        executor.shutdownNow();
    }

    @Test
    void theStoresAndSearchesAreObservedNextToTheStoreCounters() {
        service.storeDocument(new Document("record one", Map.of("documentType", "behavior", "eventId", "o-1")));
        service.searchSimilar("record");

        assertThat(operation("add").count()).isEqualTo(1);
        assertThat(operation("query").count()).isEqualTo(1);
        assertThat(meters.find(StoreFailureMetrics.FAILED).functionCounter()).isNotNull();
        assertThat(meters.find(StoreFailureMetrics.DEFERRED).functionCounter()).isNotNull();
    }

    private Timer operation(String name) {
        Timer timer = meters.find("db.vector.client.operation").tag("db.operation.name", name).timer();
        assertThat(timer).as("db.vector.client.operation " + name).isNotNull();
        return timer;
    }

    private static final class FixedEmbeddingModel implements EmbeddingModel {

        @Override
        public EmbeddingResponse call(EmbeddingRequest request) {
            List<Embedding> embeddings = new ArrayList<>();
            for (int index = 0; index < request.getInstructions().size(); index++) {
                embeddings.add(new Embedding(new float[] {1f, 0f, 0f}, index));
            }
            return new EmbeddingResponse(embeddings);
        }

        @Override
        public float[] embed(Document document) {
            return new float[] {1f, 0f, 0f};
        }

        @Override
        public int dimensions() {
            return 3;
        }
    }
}
