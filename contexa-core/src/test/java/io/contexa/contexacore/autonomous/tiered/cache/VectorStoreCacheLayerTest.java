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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VectorStoreCacheLayerTest {

    @Mock
    private VectorStore vectorStore;

    private VectorStoreCacheLayer cacheLayer;

    @BeforeEach
    void setUp() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getVectorCache().setEnabled(true);
        cacheLayer = new VectorStoreCacheLayer(vectorStore, properties);
        cacheLayer.init();
    }

    @Test
    @DisplayName("벡터 검색 실패 시 동일 요청을 즉시 두 번 호출하지 않아야 한다")
    void shouldNotRetrySameSearchImmediatelyAfterFailure() {
        SearchRequest request = SearchRequest.builder().query("query").topK(3).build();
        when(vectorStore.similaritySearch(any(SearchRequest.class))).thenThrow(new RuntimeException("busy"));

        assertThatThrownBy(() -> cacheLayer.similaritySearch(request))
                .isInstanceOf(VectorStoreCacheLayer.VectorSearchException.class)
                .hasMessageContaining("similarity search failed");

        verify(vectorStore, times(1)).similaritySearch(request);
    }
}
