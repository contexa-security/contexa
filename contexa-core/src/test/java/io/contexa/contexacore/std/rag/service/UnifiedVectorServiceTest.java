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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UnifiedVectorServiceTest {

    @Mock
    private VectorStoreCacheLayer cacheLayer;

    @Mock
    private VectorStore vectorStore;

    @Test
    @DisplayName("cache layer가 빈 결과를 반환한 정상 검색은 vectorStore를 다시 직접 호출하지 않아야 한다")
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
    @DisplayName("cache layer 검색 실패는 빈 결과로 숨기지 말고 동일 검색 재실행 없이 즉시 전파해야 한다")
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
    @DisplayName("document store가 timeout 되면 벡터 저장을 오래 기다리지 않고 VectorStoreException 으로 종료해야 한다")
    void storeDocument_shouldFailFastWhenTimeoutExceeded() {
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        properties.setStoreTimeoutMs(50);
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(properties, cacheLayer, vectorStore);
        Document document = new Document("behavior memory", Map.of("documentType", "behavior"));

        org.mockito.Mockito.doAnswer(invocation -> {
            Thread.sleep(500);
            return null;
        }).when(vectorStore).add(any());

        assertThatThrownBy(() -> unifiedVectorService.storeDocument(document))
                .isInstanceOf(VectorOperations.VectorStoreException.class)
                .hasMessageContaining("timed out");
        verify(cacheLayer, never()).invalidateAll();
    }
}
