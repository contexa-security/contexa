package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.List;
import java.util.Map;
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
        verify(cacheLayer).invalidateAll();
    }
}
