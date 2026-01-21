package io.contexa.contexacore.autonomous.tiered.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j

public class VectorStoreCacheLayer {

    @Autowired(required = false)
    private StandardVectorStoreService vectorStoreService;

    @Value("${spring.ai.security.vector-cache.max-size:10000}")
    private long maxCacheSize;

    @Value("${spring.ai.security.vector-cache.expire-minutes:5}")
    private int expireMinutes;

    @Value("${spring.ai.security.vector-cache.enabled:true}")
    private boolean cacheEnabled;

    @Value("${spring.ai.security.vector-cache.record-stats:true}")
    private boolean recordStats;

    private Cache<String, List<Document>> cache;

    @jakarta.annotation.PostConstruct
    public void init() {
        
        Caffeine<Object, Object> builder = Caffeine.newBuilder()
                .maximumSize(maxCacheSize)
                .expireAfterWrite(expireMinutes, TimeUnit.MINUTES);

        if (recordStats) {
            builder.recordStats();
        }

        cache = builder.build();

            }

    public List<Document> similaritySearch(SearchRequest request) {
        if (!cacheEnabled || vectorStoreService == null) {
            return fallbackSearch(request);
        }

        try {
            
            String cacheKey = generateCacheKey(request);

            List<Document> cachedResult = cache.getIfPresent(cacheKey);
            if (cachedResult != null) {
                                return cachedResult;
            }

                        long startTime = System.currentTimeMillis();

            List<Document> result = vectorStoreService.similaritySearch(request);

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
        
        int initialCapacity = 50 + (request.getQuery() != null ? request.getQuery().length() : 0);
        StringBuilder keyBuilder = new StringBuilder(initialCapacity);

        keyBuilder.append("q:");
        if (request.getQuery() != null) {
            keyBuilder.append(request.getQuery());
        }

        keyBuilder.append("|k:").append(request.getTopK());

        keyBuilder.append("|t:").append(request.getSimilarityThreshold());

        if (request.getFilterExpression() != null) {
            
            keyBuilder.append("|f:").append(request.getFilterExpression().hashCode());
        }

        return keyBuilder.toString();
    }

    private List<Document> fallbackSearch(SearchRequest request) {
        if (vectorStoreService == null) {
            log.warn("[VectorStoreCacheLayer] VectorStoreService not available");
            return List.of();
        }

        try {
            return vectorStoreService.similaritySearch(request);
        } catch (Exception e) {
            log.error("[VectorStoreCacheLayer] Fallback search failed", e);
            return List.of();
        }
    }

    public void add(List<Document> documents) {
        if (vectorStoreService == null) {
            log.warn("[VectorStoreCacheLayer] VectorStoreService not available for adding documents");
            return;
        }

        try {
            vectorStoreService.addDocuments(documents);
                    } catch (Exception e) {
            log.error("[VectorStoreCacheLayer] Failed to add documents to vector store", e);
        }
    }

    public void invalidate(String query) {
        if (!cacheEnabled) {
            return;
        }

        cache.asMap().keySet().stream()
                .filter(key -> key.startsWith("q:" + query))
                .forEach(cache::invalidate);

            }

    public void invalidateAll() {
        if (!cacheEnabled) {
            return;
        }

        cache.invalidateAll();
            }

    public CacheStatistics getStatistics() {
        if (!cacheEnabled || !recordStats) {
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

        public long getHitCount() { return hitCount; }
        public long getMissCount() { return missCount; }
        public double getHitRate() { return hitRate; }
        public double getMissRate() { return missRate; }
        public long getLoadSuccessCount() { return loadSuccessCount; }
        public long getLoadFailureCount() { return loadFailureCount; }
        public Duration getAverageLoadPenalty() { return averageLoadPenalty; }
        public long getEvictionCount() { return evictionCount; }
        public long getEstimatedSize() { return estimatedSize; }

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
