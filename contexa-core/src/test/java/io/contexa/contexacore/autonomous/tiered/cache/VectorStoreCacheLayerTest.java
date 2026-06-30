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
package io.contexa.contexacore.autonomous.tiered.cache;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.springframework.ai.document.Document;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VectorStoreCacheLayerTest {

    @Mock
    private VectorStore vectorStore;

    private TieredStrategyProperties properties;

    private VectorStoreCacheLayer cacheLayer;

    @BeforeEach
    void setUp() {
        properties = new TieredStrategyProperties();
        properties.getVectorCache().setEnabled(true);
        cacheLayer = new VectorStoreCacheLayer(vectorStore, properties);
        cacheLayer.init();
    }

    @Test
    @DisplayName("Vector cache is not invalidated after writes by default")
    void shouldKeepSearchCacheAfterWriteByDefault() {
        SearchRequest request = SearchRequest.builder().query("query").topK(3).build();
        when(vectorStore.similaritySearch(request)).thenReturn(List.of(new Document("cached")));

        assertThat(cacheLayer.similaritySearch(request)).hasSize(1);
        cacheLayer.invalidateAfterWrite();
        assertThat(cacheLayer.similaritySearch(request)).hasSize(1);

        verify(vectorStore, times(1)).similaritySearch(request);
    }

    @Test
    @DisplayName("Vector cache can be configured to invalidate after writes")
    void shouldInvalidateSearchCacheAfterWriteWhenConfigured() {
        properties.getVectorCache().setInvalidateOnWrite(true);
        SearchRequest request = SearchRequest.builder().query("query").topK(3).build();
        when(vectorStore.similaritySearch(request)).thenReturn(List.of(new Document("cached")));

        assertThat(cacheLayer.similaritySearch(request)).hasSize(1);
        cacheLayer.invalidateAfterWrite();
        assertThat(cacheLayer.similaritySearch(request)).hasSize(1);

        verify(vectorStore, times(2)).similaritySearch(request);
    }
    @Test
    @DisplayName("Empty vector results are cached to avoid repeated embedding/search calls")
    void shouldCacheEmptySearchResults() {
        SearchRequest request = SearchRequest.builder().query("query").topK(3).build();
        when(vectorStore.similaritySearch(request)).thenReturn(List.of());

        assertThat(cacheLayer.similaritySearch(request)).isEmpty();
        assertThat(cacheLayer.similaritySearch(request)).isEmpty();

        verify(vectorStore, times(1)).similaritySearch(request);
    }
    @Test
    @DisplayName("Failed vector searches are not hidden as successful cache entries")
    void shouldNotRetrySameSearchImmediatelyAfterFailure() {
        SearchRequest request = SearchRequest.builder().query("query").topK(3).build();
        when(vectorStore.similaritySearch(any(SearchRequest.class))).thenThrow(new RuntimeException("busy"));

        assertThatThrownBy(() -> cacheLayer.similaritySearch(request))
                .isInstanceOf(VectorStoreCacheLayer.VectorSearchException.class)
                .hasMessageContaining("similarity search failed");

        verify(vectorStore, times(1)).similaritySearch(request);
    }
    @Test
    @DisplayName("Equivalent filter expressions share the same vector cache key")
    void shouldReuseCacheForEquivalentFilterExpressions() {
        FilterExpressionBuilder firstBuilder = new FilterExpressionBuilder();
        FilterExpressionBuilder secondBuilder = new FilterExpressionBuilder();
        SearchRequest firstRequest = SearchRequest.builder()
                .query("query")
                .topK(3)
                .filterExpression(firstBuilder.and(
                        firstBuilder.eq("documentType", "behavior"),
                        firstBuilder.eq("userId", "admin")).build())
                .build();
        SearchRequest secondRequest = SearchRequest.builder()
                .query("query")
                .topK(3)
                .filterExpression(secondBuilder.and(
                        secondBuilder.eq("documentType", "behavior"),
                        secondBuilder.eq("userId", "admin")).build())
                .build();
        when(vectorStore.similaritySearch(any(SearchRequest.class))).thenReturn(List.of(new Document("cached")));

        assertThat(cacheLayer.similaritySearch(firstRequest)).hasSize(1);
        assertThat(cacheLayer.similaritySearch(secondRequest)).hasSize(1);

        verify(vectorStore, times(1)).similaritySearch(any(SearchRequest.class));
    }
    @Test
    @DisplayName("Concurrent cache misses for the same search are coalesced into one vector call")
    void shouldCoalesceConcurrentSameSearchMisses() throws Exception {
        SearchRequest request = SearchRequest.builder().query("query").topK(3).build();
        CountDownLatch loaderEntered = new CountDownLatch(1);
        CountDownLatch releaseLoader = new CountDownLatch(1);
        when(vectorStore.similaritySearch(request)).thenAnswer(invocation -> {
            loaderEntered.countDown();
            assertThat(releaseLoader.await(5, TimeUnit.SECONDS)).isTrue();
            return List.of(new Document("cached"));
        });

        int threads = 20;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<List<Document>>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(executor.submit(() -> {
                    assertThat(start.await(5, TimeUnit.SECONDS)).isTrue();
                    return cacheLayer.similaritySearch(request);
                }));
            }
            start.countDown();
            assertThat(loaderEntered.await(5, TimeUnit.SECONDS)).isTrue();
            releaseLoader.countDown();

            for (Future<List<Document>> future : futures) {
                assertThat(future.get(5, TimeUnit.SECONDS)).hasSize(1);
            }
        } finally {
            executor.shutdownNow();
        }

        verify(vectorStore, times(1)).similaritySearch(request);
    }
}


