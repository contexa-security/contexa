package io.contexa.contexacore.autonomous.tiered.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexacore.properties.TieredStrategyProperties;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
public class VectorStoreCacheLayer {

    private final VectorStore vectorStore;
    private final TieredStrategyProperties tieredStrategyProperties;

    public VectorStoreCacheLayer(VectorStore vectorStore, TieredStrategyProperties tieredStrategyProperties) {
        this.vectorStore = vectorStore;
        this.tieredStrategyProperties = tieredStrategyProperties;
    }

    private Cache<String, List<Document>> cache;

    @PostConstruct
    public void init() {
        TieredStrategyProperties.VectorCache vectorCache = tieredStrategyProperties.getVectorCache();

        Caffeine<Object, Object> builder = Caffeine.newBuilder()
                .maximumSize(vectorCache.getMaxSize())
                .expireAfterWrite(vectorCache.getExpireMinutes(), TimeUnit.MINUTES);

        if (vectorCache.isRecordStats()) {
            builder.recordStats();
        }

        cache = builder.build();

    }

    public List<Document> similaritySearch(SearchRequest request) {
        if (!tieredStrategyProperties.getVectorCache().isEnabled() || vectorStore == null) {
            return fallbackSearch(request);
        }

        try {
            String cacheKey = generateCacheKey(request);

            List<Document> cachedResult = cache.getIfPresent(cacheKey);
            if (cachedResult != null) {
                return cachedResult;
            }

            long startTime = System.currentTimeMillis();

            List<Document> result = vectorStore.similaritySearch(request);

            long elapsedTime = System.currentTimeMillis() - startTime;

            if (result != null && !result.isEmpty()) {
                cache.put(cacheKey, result);
            }

            return result;

        } catch (Exception e) {
            log.error("[VectorStoreCacheLayer] Error during similarity search", e);
            return fallbackSearch(request);
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

            keyBuilder.append("|f:").append(request.getFilterExpression().hashCode());
        }

        return keyBuilder.toString();
    }

    private List<Document> fallbackSearch(SearchRequest request) {
        if (vectorStore == null) {
            log.error("[VectorStoreCacheLayer] VectorStore not available");
            return List.of();
        }

        try {
            return vectorStore.similaritySearch(request);
        } catch (Exception e) {
            log.error("[VectorStoreCacheLayer] Fallback search failed", e);
            return List.of();
        }
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
        }
    }

    public void invalidate(String query) {
        if (!tieredStrategyProperties.getVectorCache().isEnabled()) {
            return;
        }

        cache.asMap().keySet().stream()
                .filter(key -> key.startsWith("q:" + query))
                .forEach(cache::invalidate);

    }

    public void invalidateAll() {
        if (!tieredStrategyProperties.getVectorCache().isEnabled()) {
            return;
        }

        cache.invalidateAll();
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
            return String.format(
                    "CacheStatistics{hitRate=%.2f%%, missRate=%.2f%%, size=%d, evictions=%d, avgLoadTime=%dms}",
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
