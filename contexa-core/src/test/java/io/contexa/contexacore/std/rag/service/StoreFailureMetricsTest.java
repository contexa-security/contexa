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

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.properties.VectorStoreRetryProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class StoreFailureMetricsTest {

    @Test
    @DisplayName("the registry shows the failed, pending, retried and dropped stores as they change (BR-C4)")
    void theRegistryShowsTheCountsAsTheyChange() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            FlakyVectorStore store = new FlakyVectorStore().goDown();
            ManualRetryScheduler scheduler = new ManualRetryScheduler();
            VectorStoreRetryProperties retry = new VectorStoreRetryProperties();
            retry.setQueueSize(2);
            UnifiedVectorService service = new UnifiedVectorService(new PgVectorStoreProperties(),
                    mock(VectorStoreCacheLayer.class), store, executor, retry, null, new MutableClock(), scheduler);
            SimpleMeterRegistry registry = new SimpleMeterRegistry();
            new StoreFailureMetrics(service).bindTo(registry);

            for (int number = 1; number <= 3; number++) {
                try {
                    service.storeDocument(new Document("record " + number,
                            Map.of("documentType", "behavior", "eventId", "event-" + number)));
                } catch (VectorOperations.VectorStoreException expected) {
                    // the caller sees the failure; the document waits for a retry
                }
            }

            assertThat(registry.get("contexa.vector.store.failed").functionCounter().count()).isEqualTo(3.0);
            assertThat(registry.get("contexa.vector.store.pending").gauge().value()).isEqualTo(2.0);
            assertThat(registry.get("contexa.vector.store.retried").functionCounter().count()).isZero();
            assertThat(registry.get("contexa.vector.store.dropped").functionCounter().count()).isEqualTo(1.0);

            store.recover();
            scheduler.runUntilIdle(10);

            assertThat(registry.get("contexa.vector.store.failed").functionCounter().count()).isEqualTo(3.0);
            assertThat(registry.get("contexa.vector.store.pending").gauge().value()).isZero();
            assertThat(registry.get("contexa.vector.store.retried").functionCounter().count()).isEqualTo(2.0);
            assertThat(registry.get("contexa.vector.store.dropped").functionCounter().count()).isEqualTo(1.0);
        } finally {
            executor.shutdownNow();
        }
    }
}
