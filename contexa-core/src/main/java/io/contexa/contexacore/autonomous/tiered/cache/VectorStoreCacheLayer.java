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

import java.util.Locale;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexacommon.cache.ContexaCaffeine;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.rag.service.PgVectorSearchSettings;
import io.contexa.contexacore.std.rag.service.VectorSearchScope;

import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

@Slf4j
public class VectorStoreCacheLayer {

    public static class VectorSearchException extends RuntimeException {
        public VectorSearchException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private final VectorStore vectorStore;
    private final TieredStrategyProperties tieredStrategyProperties;

    public VectorStoreCacheLayer(VectorStore vectorStore, TieredStrategyProperties tieredStrategyProperties) {
        this.vectorStore = vectorStore;
        this.tieredStrategyProperties = tieredStrategyProperties;
    }

    /** A cache whose searches run with the pgvector settings they need (W2-15). */
    public VectorStoreCacheLayer(VectorStore vectorStore, TieredStrategyProperties tieredStrategyProperties,
                                 PgVectorSearchSettings searchSettings) {
        this.vectorStore = vectorStore;
        this.tieredStrategyProperties = tieredStrategyProperties;
        this.searchSettings = searchSettings;
    }

    /**
     * After a write, clears the cached searches the written documents can change: their users', their organisations'
     * and those that require neither (W2-15). Other users' searches stay cached.
     */
    public void invalidateAfterWrite(Collection<Document> documents) {
        if (!tieredStrategyProperties.getVectorCache().isEnabled()
                || !tieredStrategyProperties.getVectorCache().isInvalidateOnWrite()
                || documents == null || documents.isEmpty()) {
            return;
        }
        List<VectorSearchScope> written = documents.stream().map(VectorSearchScope::ofDocument).toList();
        invalidateMatching(search -> written.stream().anyMatch(scope -> scope.reaches(search)));
    }

    /** After a user's records are purged, clears that user's cached searches and those that require no user (W2-15). */
    public void invalidateForUser(String userId) {
        if (!tieredStrategyProperties.getVectorCache().isEnabled() || userId == null) {
            return;
        }
        VectorSearchScope purged = new VectorSearchScope(userId, null);
        invalidateMatching(purged::reaches);
    }

    private void invalidateMatching(Predicate<VectorSearchScope> reached) {
        for (String key : List.copyOf(cache.asMap().keySet())) {
            if (reached.test(scopes.getOrDefault(key, UNSCOPED))) {
                cache.invalidate(key);
                scopes.remove(key);
            }
        }
    }

    private static final VectorSearchScope UNSCOPED = new VectorSearchScope(null, null);
    /** PR-91: the documents kept may take a thirty-second of the maximum heap, within these bounds. */
    private static final int CACHE_HEAP_SHARE_DIVISOR = 32;
    private static final long MIN_CACHE_BYTES = 8L * 1024 * 1024;
    private static final long MAX_CACHE_BYTES = 128L * 1024 * 1024;
    /** What a document takes around its text and metadata. */
    private static final long DOCUMENT_BYTES = 256;

    private Cache<String, List<Document>> cache;
    /** The scope of each cached search, so that a write clears only the searches it can change (W2-15). */
    private final ConcurrentHashMap<String, VectorSearchScope> scopes = new ConcurrentHashMap<>();
    private PgVectorSearchSettings searchSettings;

    @PostConstruct
    public void init() {
        TieredStrategyProperties.VectorCache vectorCache = tieredStrategyProperties.getVectorCache();

        // PR-91: a search weighs its documents and at least its share of the budget, so that the number of searches
        // set for the cache holds as well: a search kept or not gives the same documents, one not kept is searched again.
        int maxSearches = vectorCache.getMaxSize();
        long budget = maxSearches > 0 ? defaultCacheBudgetBytes(Runtime.getRuntime().maxMemory()) : 0;
        long searchShare = maxSearches > 0 ? (budget + maxSearches - 1) / maxSearches : 0;

        Caffeine<String, List<Document>> builder = ContexaCaffeine.newBuilder()
                .maximumWeight(budget)
                .weigher((String key, List<Document> documents) ->
                        (int) Math.min(Integer.MAX_VALUE, Math.max(searchShare, documentsBytes(documents))))
                .expireAfterWrite(vectorCache.getExpireMinutes(), TimeUnit.MINUTES)
                .evictionListener((key, value, cause) -> {
                    if (key != null) {
                        scopes.remove(key);
                    }
                });

        if (vectorCache.isRecordStats()) {
            builder.recordStats();
        }

        cache = builder.build();

    }

    public List<Document> similaritySearch(SearchRequest request) {
        if (!tieredStrategyProperties.getVectorCache().isEnabled() || vectorStore == null) {
            return searchWithoutCache(request);
        }

        try {
            String cacheKey = generateCacheKey(request);

            // The scope goes in before the search is kept, so that whatever removes the search removes its scope.
            return cache.get(cacheKey, ignored -> {
                List<Document> result = search(request);
                scopes.put(cacheKey, VectorSearchScope.of(request.getFilterExpression()));
                return result != null ? List.copyOf(result) : List.of();
            });

        } catch (Exception e) {
            log.error("[VectorStoreCacheLayer] Error during similarity search", e);
            throw new VectorSearchException("Vector store similarity search failed", e);
        }
    }

    private String generateCacheKey(SearchRequest request) {

        int initialCapacity = 50 + request.getQuery().length();
        StringBuilder keyBuilder = new StringBuilder(initialCapacity);

        keyBuilder.append("q:");
        keyBuilder.append(request.getQuery());

        keyBuilder.append("|k:").append(request.getTopK());

        keyBuilder.append("|t:").append(request.getSimilarityThreshold());

        if (request.getFilterExpression() != null) {

            keyBuilder.append("|f:").append(stableFilterExpression(request.getFilterExpression()));
        }

        return keyBuilder.toString();
    }

    private String stableFilterExpression(Object filterExpression) {
        return String.valueOf(filterExpression);
    }

    private List<Document> searchWithoutCache(SearchRequest request) {
        if (vectorStore == null) {
            log.error("[VectorStoreCacheLayer] VectorStore not available");
            return List.of();
        }

        try {
            return search(request);
        } catch (Exception e) {
            log.error("[VectorStoreCacheLayer] Fallback search failed", e);
            throw new VectorSearchException("Vector store fallback search failed", e);
        }
    }

    /** The store's search, with the pgvector settings the request needs when the store is pgvector (W2-15). */
    private List<Document> search(SearchRequest request) {
        return searchSettings != null ? searchSettings.search(vectorStore, request) : vectorStore.similaritySearch(request);
    }

    public void add(List<Document> documents) {
        if (vectorStore == null) {
            log.error("[VectorStoreCacheLayer] VectorStore not available for adding documents");
            return;
        }

        try {
            vectorStore.add(documents);
        } catch (Exception e) {
            log.error("[VectorStoreCacheLayer] Failed to add documents to vector store", e);
            throw new VectorSearchException("Failed to add documents to vector store", e);
        }
    }

    public void invalidate(String query) {
        if (!tieredStrategyProperties.getVectorCache().isEnabled()) {
            return;
        }

        cache.asMap().keySet().stream()
                .filter(key -> key.startsWith("q:" + query))
                .forEach(key -> {
                    cache.invalidate(key);
                    scopes.remove(key);
                });

    }

    public void invalidateAfterWrite() {
        if (!tieredStrategyProperties.getVectorCache().isEnabled()
                || !tieredStrategyProperties.getVectorCache().isInvalidateOnWrite()) {
            return;
        }

        cache.invalidateAll();
        scopes.clear();
    }

    public void invalidateAll() {
        if (!tieredStrategyProperties.getVectorCache().isEnabled()) {
            return;
        }

        cache.invalidateAll();
        scopes.clear();
    }

    /**
     * PR-91: the limit of the documents kept for a maximum heap of {@code maxHeapBytes}: a thirty-second of it, between
     * 8 MiB and 128 MiB. A 512 MiB heap gives 16 MiB, 2 GiB 64 MiB, 4 GiB or more 128 MiB.
     */
    static long defaultCacheBudgetBytes(long maxHeapBytes) {
        return Math.max(MIN_CACHE_BYTES, Math.min(MAX_CACHE_BYTES, maxHeapBytes / CACHE_HEAP_SHARE_DIVISOR));
    }

    /** Their text and metadata at two bytes a character. */
    private static long documentsBytes(List<Document> documents) {
        long bytes = 0;
        for (Document document : documents) {
            String text = document.getText();
            bytes += DOCUMENT_BYTES + 2L * ((text != null ? text.length() : 0) + document.getMetadata().toString().length());
        }
        return bytes;
    }

    /** The bytes the documents kept are counted at (PR-91). */
    long cachedBytes() {
        cache.cleanUp();
        return cache.policy().eviction().orElseThrow().weightedSize().orElseThrow();
    }

    /** How many searches are kept. */
    long cachedSearches() {
        cache.cleanUp();
        return cache.asMap().size();
    }

    /** How many searches have a scope kept for them. */
    long scopedSearches() {
        cache.cleanUp();
        return scopes.size();
    }

    public CacheStatistics getStatistics() {
        if (!tieredStrategyProperties.getVectorCache().isEnabled() || !tieredStrategyProperties.getVectorCache().isRecordStats()) {
            return CacheStatistics.empty();
        }

        CacheStats stats = cache.stats();

        return CacheStatistics.builder()
                .hitCount(stats.hitCount())
                .missCount(stats.missCount())
                .hitRate(stats.hitRate())
                .missRate(stats.missRate())
                .loadSuccessCount(stats.loadSuccessCount())
                .loadFailureCount(stats.loadFailureCount())
                .averageLoadPenalty(Duration.ofNanos((long) stats.averageLoadPenalty()))
                .evictionCount(stats.evictionCount())
                .estimatedSize(cache.estimatedSize())
                .build();
    }

    public static class CacheStatistics {
        private final long hitCount;
        private final long missCount;
        private final double hitRate;
        private final double missRate;
        private final long loadSuccessCount;
        private final long loadFailureCount;
        private final Duration averageLoadPenalty;
        private final long evictionCount;
        private final long estimatedSize;

        private CacheStatistics(Builder builder) {
            this.hitCount = builder.hitCount;
            this.missCount = builder.missCount;
            this.hitRate = builder.hitRate;
            this.missRate = builder.missRate;
            this.loadSuccessCount = builder.loadSuccessCount;
            this.loadFailureCount = builder.loadFailureCount;
            this.averageLoadPenalty = builder.averageLoadPenalty;
            this.evictionCount = builder.evictionCount;
            this.estimatedSize = builder.estimatedSize;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static CacheStatistics empty() {
            return new Builder().build();
        }

        public long getHitCount() {
            return hitCount;
        }

        public long getMissCount() {
            return missCount;
        }

        public double getHitRate() {
            return hitRate;
        }

        public double getMissRate() {
            return missRate;
        }

        public long getLoadSuccessCount() {
            return loadSuccessCount;
        }

        public long getLoadFailureCount() {
            return loadFailureCount;
        }

        public Duration getAverageLoadPenalty() {
            return averageLoadPenalty;
        }

        public long getEvictionCount() {
            return evictionCount;
        }

        public long getEstimatedSize() {
            return estimatedSize;
        }

        @Override
        public String toString() {
            return String.format(Locale.ROOT, "CacheStatistics{hitRate=%.2f%%, missRate=%.2f%%, size=%d, evictions=%d, avgLoadTime=%dms}",
                    hitRate * 100, missRate * 100, estimatedSize, evictionCount,
                    averageLoadPenalty != null ? averageLoadPenalty.toMillis() : 0
            );
        }

        public static class Builder {
            private long hitCount;
            private long missCount;
            private double hitRate;
            private double missRate;
            private long loadSuccessCount;
            private long loadFailureCount;
            private Duration averageLoadPenalty = Duration.ZERO;
            private long evictionCount;
            private long estimatedSize;

            public Builder hitCount(long hitCount) {
                this.hitCount = hitCount;
                return this;
            }

            public Builder missCount(long missCount) {
                this.missCount = missCount;
                return this;
            }

            public Builder hitRate(double hitRate) {
                this.hitRate = hitRate;
                return this;
            }

            public Builder missRate(double missRate) {
                this.missRate = missRate;
                return this;
            }

            public Builder loadSuccessCount(long loadSuccessCount) {
                this.loadSuccessCount = loadSuccessCount;
                return this;
            }

            public Builder loadFailureCount(long loadFailureCount) {
                this.loadFailureCount = loadFailureCount;
                return this;
            }

            public Builder averageLoadPenalty(Duration averageLoadPenalty) {
                this.averageLoadPenalty = averageLoadPenalty;
                return this;
            }

            public Builder evictionCount(long evictionCount) {
                this.evictionCount = evictionCount;
                return this;
            }

            public Builder estimatedSize(long estimatedSize) {
                this.estimatedSize = estimatedSize;
                return this;
            }

            public CacheStatistics build() {
                return new CacheStatistics(this);
            }
        }
    }
}


