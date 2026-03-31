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
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
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
    @DisplayName("similarity search 가 timeout 되면 embed 응답을 기다리지 않고 VectorStoreException 으로 실패해야 한다")
    void searchSimilar_shouldFailFastWhenTimeoutExceeded() {
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        properties.setSearchTimeoutMs(50);
        AtomicBoolean interrupted = new AtomicBoolean(false);
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(properties, cacheLayer, vectorStore);

        when(cacheLayer.similaritySearch(any(SearchRequest.class))).thenReturn(List.of());
        when(vectorStore.similaritySearch(any(SearchRequest.class))).thenAnswer(invocation -> {
            try {
                Thread.sleep(500);
            } catch (InterruptedException interruptedException) {
                interrupted.set(true);
                Thread.currentThread().interrupt();
            }
            return List.of();
        });

        assertThatThrownBy(() -> unifiedVectorService.searchSimilar("Path: /admin/api/security-test/sensitive/resource-001"))
                .isInstanceOf(VectorOperations.VectorStoreException.class)
                .hasMessageContaining("Similarity search failed");
        verify(cacheLayer, never()).invalidateAll();
        org.assertj.core.api.Assertions.assertThat(interrupted.get()).isTrue();
    }

    @Test
    @DisplayName("document store 가 timeout 되면 벡터 저장을 오래 기다리지 않고 VectorStoreException 으로 종료해야 한다")
    void storeDocument_shouldFailFastWhenTimeoutExceeded() {
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        properties.setStoreTimeoutMs(50);
        AtomicBoolean interrupted = new AtomicBoolean(false);
        UnifiedVectorService unifiedVectorService = new UnifiedVectorService(properties, cacheLayer, vectorStore);
        Document document = new Document("behavior memory", Map.of("documentType", "behavior"));

        org.mockito.Mockito.doAnswer(invocation -> {
            try {
                Thread.sleep(500);
            } catch (InterruptedException interruptedException) {
                interrupted.set(true);
                Thread.currentThread().interrupt();
            }
            return null;
        }).when(vectorStore).add(any());

        assertThatThrownBy(() -> unifiedVectorService.storeDocument(document))
                .isInstanceOf(VectorOperations.VectorStoreException.class)
                .hasMessageContaining("timed out");
        verify(cacheLayer, never()).invalidateAll();
        org.assertj.core.api.Assertions.assertThat(interrupted.get()).isTrue();
    }
}
