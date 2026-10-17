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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UnifiedVectorServiceTest {

    @Mock
    private VectorStoreCacheLayer cacheLayer;

    @Mock
    private VectorStore vectorStore;

    @Test
    @DisplayName("searchSimilar does not call vectorStore directly when cacheLayer returns an empty result")
    void searchSimilar_shouldNotRepeatSearchWhenCacheLayerReturnsEmptyResult() {
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(properties, cacheLayer, vectorStore);
        SearchRequest request = SearchRequest.builder().query("query").topK(3).build();

        when(cacheLayer.similaritySearch(request)).thenReturn(List.of());

        List<Document> result = unifiedVectorService.searchSimilar(request);

        assertThat(result).isEmpty();
        verify(cacheLayer).similaritySearch(request);
        verify(vectorStore, never()).similaritySearch(any(SearchRequest.class));
    }

    @Test
    @DisplayName("searchSimilar propagates a non-retryable cache failure without repeating the same search")
    void searchSimilar_shouldPropagateCacheLayerFailureWithoutRetryingSameSearch() {
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(properties, cacheLayer, vectorStore);
        SearchRequest request = SearchRequest.builder().query("query").topK(3).build();

        doThrow(new VectorStoreCacheLayer.VectorSearchException("busy", new RuntimeException("503")))
                .when(cacheLayer)
                .similaritySearch(request);

        assertThatThrownBy(() -> unifiedVectorService.searchSimilar(request))
                .isInstanceOf(VectorOperations.VectorStoreException.class)
                .hasMessageContaining("Similarity search failed");
        verify(cacheLayer).similaritySearch(request);
        verify(vectorStore, never()).similaritySearch(any(SearchRequest.class));
    }

    @Test
    @DisplayName("storeDocument fails fast when the vector store exceeds the timeout")
    void storeDocument_shouldFailFastWhenTimeoutExceeded() {
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        properties.setStoreTimeoutMs(50);
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(properties, cacheLayer, vectorStore);
        Document document = new Document("behavior memory", Map.of("documentType", "behavior"));

        doAnswer(invocation -> {
            Thread.sleep(500);
            return null;
        }).when(vectorStore).add(any());

        assertThatThrownBy(() -> unifiedVectorService.storeDocument(document))
                .isInstanceOf(VectorOperations.VectorStoreException.class)
                .hasMessageContaining("timed out");
        verify(cacheLayer, never()).invalidateAll();
    }

    @Test
    @DisplayName("storeDocument retries a retryable busy failure and succeeds on the next attempt")
    void storeDocument_shouldRetryBusyFailureAndInvalidateCacheOnSuccess() {
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(properties, cacheLayer, vectorStore);
        Document document = new Document("behavior memory", Map.of("documentType", "behavior"));
        AtomicInteger attempts = new AtomicInteger(0);

        doAnswer(invocation -> {
            if (attempts.getAndIncrement() == 0) {
                throw new RuntimeException("HTTP 503 - {\"error\":\"server busy, please try again.  maximum pending requests exceeded\"}");
            }
            return null;
        }).when(vectorStore).add(any());

        unifiedVectorService.storeDocument(document);

        verify(vectorStore, times(2)).add(any());
        verify(cacheLayer).invalidateAfterWrite(any());
    }

    @Test
    @DisplayName("an event's document gets an id from the event and its type, so storing it again overwrites it (W2-15)")
    @SuppressWarnings("unchecked")
    void storeDocument_givesAnEventsDocumentAStableId() {
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(new PgVectorStoreProperties(), cacheLayer,
                vectorStore);
        String expected = UUID.nameUUIDFromBytes("behavior:event-1".getBytes(StandardCharsets.UTF_8)).toString();

        unifiedVectorService.storeDocument(new Document("first", Map.of("documentType", "behavior", "eventId", "event-1")));
        unifiedVectorService.storeDocument(new Document("again", Map.of("documentType", "behavior", "eventId", "event-1")));
        unifiedVectorService.storeDocument(new Document("threat", Map.of("documentType", "threat", "eventId", "event-1")));

        ArgumentCaptor<List<Document>> stored = ArgumentCaptor.forClass(List.class);
        verify(vectorStore, times(3)).add(stored.capture());
        List<Document> documents = stored.getAllValues().stream().map(batch -> batch.get(0)).toList();
        assertThat(documents.get(0).getId()).isEqualTo(expected);
        assertThat(documents.get(1).getId()).isEqualTo(expected);
        assertThat(documents.get(1).getText()).isEqualTo("again");
        assertThat(documents.get(2).getId()).isNotEqualTo(expected);
        assertThat(documents).allSatisfy(document -> assertThat(document.getMetadata()).containsEntry("id", document.getId()));
    }

    @Test
    @DisplayName("documentId names the id an event's record is stored under, so it can be removed by its event (Q-15)")
    @SuppressWarnings("unchecked")
    void documentId_isTheIdAnEventsRecordIsStoredUnder() {
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(new PgVectorStoreProperties(), cacheLayer,
                vectorStore);

        unifiedVectorService.storeDocument(new Document("late",
                Map.of("documentType", "threat", "eventId", "event-2")));

        ArgumentCaptor<List<Document>> stored = ArgumentCaptor.forClass(List.class);
        verify(vectorStore).add(stored.capture());
        assertThat(stored.getValue().get(0).getId()).isEqualTo(UnifiedVectorService.documentId("threat", "event-2"));
    }

    @Test
    @DisplayName("a document without an event keeps its own id, and its metadata names the same id (W2-15)")
    @SuppressWarnings("unchecked")
    void storeDocument_keepsTheIdOfADocumentWithoutAnEvent() {
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(new PgVectorStoreProperties(), cacheLayer,
                vectorStore);
        Document document = new Document("policy note", Map.of("documentType", "policy"));

        unifiedVectorService.storeDocument(document);

        ArgumentCaptor<List<Document>> stored = ArgumentCaptor.forClass(List.class);
        verify(vectorStore).add(stored.capture());
        assertThat(stored.getValue().get(0).getId()).isEqualTo(document.getId());
        assertThat(stored.getValue().get(0).getMetadata()).containsEntry("id", document.getId());
    }

    @Test
    @DisplayName("a store clears the cached searches of the stored documents (W2-15)")
    @SuppressWarnings("unchecked")
    void storeDocument_clearsTheCachedSearchesOfTheStoredDocuments() {
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(new PgVectorStoreProperties(), cacheLayer,
                vectorStore);

        unifiedVectorService.storeDocument(new Document("memory", Map.of("documentType", "behavior", "userId", "alice")));

        ArgumentCaptor<List<Document>> invalidated = ArgumentCaptor.forClass(List.class);
        verify(cacheLayer).invalidateAfterWrite(invalidated.capture());
        assertThat(invalidated.getValue()).singleElement()
                .satisfies(document -> assertThat(document.getMetadata()).containsEntry("userId", "alice"));
    }

    @Test
    @DisplayName("vector writes run on the vector executor and carry no engine database transaction (W2-15)")
    void vectorWritesCarryNoEngineTransaction() throws NoSuchMethodException {
        assertThat(UnifiedVectorService.class.getMethod("storeDocument", Document.class)
                .isAnnotationPresent(Transactional.class)).isFalse();
        assertThat(UnifiedVectorService.class.getMethod("storeDocuments", List.class)
                .isAnnotationPresent(Transactional.class)).isFalse();
        assertThat(UnifiedVectorService.class.getMethod("deleteDocuments", List.class)
                .isAnnotationPresent(Transactional.class)).isFalse();
    }

    @Test
    @DisplayName("searchSimilar should escape literal filter values before building a vector filter expression")
    void searchSimilar_shouldEscapeLiteralFilterValues() {
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(properties, cacheLayer, vectorStore);
        when(cacheLayer.similaritySearch(any(SearchRequest.class))).thenReturn(List.of());

        unifiedVectorService.searchSimilar("query", Map.of("userId", "alice' || true || 'x"));

        ArgumentCaptor<SearchRequest> captor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(cacheLayer).similaritySearch(captor.capture());
        // One equality on the whole value: Spring AI 1.1.5 and later read the escaped quotes back as the literal value
        // (P2 correction 6); earlier versions kept the escape characters in it.
        assertThat(captor.getValue().getFilterExpression().toString())
                .contains("type=EQ")
                .contains("value=alice' || true || 'x]")
                .doesNotContain("type=OR");
    }

    @Test
    @DisplayName("searchSimilar should reject unsafe vector filter keys")
    void searchSimilar_shouldRejectUnsafeFilterKeys() {
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(properties, cacheLayer, vectorStore);

        assertThatThrownBy(() -> unifiedVectorService.searchSimilar("query", Map.of("userId || true", "alice")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsafe vector filter key");
        verify(cacheLayer, never()).similaritySearch(any(SearchRequest.class));
    }
}
