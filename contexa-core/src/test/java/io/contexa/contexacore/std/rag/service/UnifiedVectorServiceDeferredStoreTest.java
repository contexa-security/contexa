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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;
import org.springframework.ai.document.MetadataMode;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * QF-25 (b): a document left for later is stored by the retry from its own thread and counted as deferred, not as
 * failed. BR-S2: a stored document names the embedding model, which stays out of the text a provider embeds.
 */
class UnifiedVectorServiceDeferredStoreTest {

    private final MutableClock clock = new MutableClock();
    private final ManualRetryScheduler scheduler = new ManualRetryScheduler();
    private final FlakyVectorStore store = new FlakyVectorStore();
    private final VectorStoreCacheLayer cacheLayer = mock(VectorStoreCacheLayer.class);
    private ExecutorService executor;

    @BeforeEach
    void setUp() {
        executor = Executors.newFixedThreadPool(2);
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    private UnifiedVectorService service(VectorStoreRetryProperties retry) {
        return new UnifiedVectorService(new PgVectorStoreProperties(), cacheLayer, store, executor, retry, null, clock,
                scheduler);
    }

    private static Document record(int number) {
        return new Document("record " + number,
                Map.of("documentType", "behavior", "eventId", "event-" + number, "userId", "alice"));
    }

    @Test
    void aDeferredDocumentIsStoredByTheRetryAndCountedAsDeferred() {
        UnifiedVectorService service = service(new VectorStoreRetryProperties());

        service.storeLater(record(1));

        assertThat(store.rows()).isEmpty();
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(0, 1, 0, 0, 1));

        scheduler.runUntilIdle(5);

        assertThat(store.rows()).containsOnlyKeys(UnifiedVectorService.documentId("behavior", "event-1"));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(0, 0, 1, 0, 1));
    }

    @Test
    void withoutTheRetryADeferredDocumentIsStoredAtOnce() {
        VectorStoreRetryProperties off = new VectorStoreRetryProperties();
        off.setEnabled(false);
        UnifiedVectorService service = service(off);

        service.storeLater(record(2));

        assertThat(store.rows()).containsOnlyKeys(UnifiedVectorService.documentId("behavior", "event-2"));
        assertThat(service.storeFailureStats()).isEqualTo(StoreFailureStats.NONE);
    }

    @Test
    void aStoredDocumentNamesTheEmbeddingModelOutsideTheEmbeddedText() {
        UnifiedVectorService service = service(new VectorStoreRetryProperties());
        service.setEmbeddingModelSource(() -> "ollama/mxbai-embed-large");

        service.storeDocument(record(3));

        Document stored = store.rows().get(UnifiedVectorService.documentId("behavior", "event-3"));
        assertThat(stored.getMetadata()).containsEntry("embeddingModel", "ollama/mxbai-embed-large");
        Map<String, Object> withoutModel = new HashMap<>(stored.getMetadata());
        withoutModel.remove("embeddingModel");
        Document before = Document.builder().id(stored.getId()).text(stored.getText()).metadata(withoutModel).build();
        assertThat(stored.getFormattedContent(MetadataMode.EMBED))
                .isEqualTo(before.getFormattedContent(MetadataMode.EMBED))
                .doesNotContain("embeddingModel");
        assertThat(stored.getFormattedContent(MetadataMode.ALL)).contains("embeddingModel");
    }

    @Test
    void withoutAKnownModelOrWithTheCallersOwnNothingIsChanged() {
        UnifiedVectorService unknown = service(new VectorStoreRetryProperties());
        unknown.setEmbeddingModelSource(() -> {
            throw new IllegalStateException("no binding");
        });
        unknown.storeDocument(record(4));
        assertThat(store.rows().get(UnifiedVectorService.documentId("behavior", "event-4")).getMetadata())
                .doesNotContainKey("embeddingModel");

        UnifiedVectorService known = service(new VectorStoreRetryProperties());
        known.setEmbeddingModelSource(() -> "openai/text-embedding-3-small");
        known.storeDocument(new Document("record 5", Map.of("documentType", "behavior", "eventId", "event-5",
                "embeddingModel", "ollama/bge-m3")));
        assertThat(store.rows().get(UnifiedVectorService.documentId("behavior", "event-5")).getMetadata())
                .containsEntry("embeddingModel", "ollama/bge-m3");
    }
}
