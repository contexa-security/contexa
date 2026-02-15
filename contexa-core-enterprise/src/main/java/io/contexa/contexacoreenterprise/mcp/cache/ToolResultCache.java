package io.contexa.contexacoreenterprise.mcp.cache;

import io.contexa.contexacoreenterprise.mcp.tool.execution.ToolExecutor;
import io.contexa.contexacoreenterprise.properties.ToolProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class ToolResultCache {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ToolProperties toolProperties;

    public ToolResultCache(RedisTemplate<String, Object> redisTemplate, ToolProperties toolProperties) {
        this.redisTemplate = redisTemplate;
        this.toolProperties = toolProperties;
    }

    private final Map<String, CacheEntry> localCache = new ConcurrentHashMap<>();

    private final AtomicLong hitCount = new AtomicLong(0);
    private final AtomicLong missCount = new AtomicLong(0);
    private final AtomicLong putCount = new AtomicLong(0);
    private final AtomicLong evictionCount = new AtomicLong(0);

    public ToolExecutor.ToolResult get(String key) {
        if (!toolProperties.getCache().isEnabled()) {
            return null;
        }

        CacheEntry localEntry = localCache.get(key);
        if (localEntry != null && !localEntry.isExpired()) {
            hitCount.incrementAndGet();
                        return localEntry.getValue();
        }

        try {
            Object cached = redisTemplate.opsForValue().get(formatRedisKey(key));
            if (cached instanceof ToolExecutor.ToolResult) {
                hitCount.incrementAndGet();

                putToLocalCache(key, (ToolExecutor.ToolResult) cached);
                
                return (ToolExecutor.ToolResult) cached;
            }
        } catch (Exception e) {
            log.error("Redis cache read failed: {}", e.getMessage());
        }
        
        missCount.incrementAndGet();
                return null;
    }

    public Optional<ToolExecutor.ToolResult> getOptional(String key) {
        return Optional.ofNullable(get(key));
    }

    public void put(String key, ToolExecutor.ToolResult value) {
        put(key, value, Duration.ofSeconds(toolProperties.getCache().getDefaultTtl()));
    }

    public void put(String key, ToolExecutor.ToolResult value, Duration ttl) {
        if (!toolProperties.getCache().isEnabled() || value == null) {
            return;
        }
        
        putCount.incrementAndGet();

        putToLocalCache(key, value);

        try {
            redisTemplate.opsForValue().set(
                formatRedisKey(key), 
                value, 
                ttl
            );
                    } catch (Exception e) {
            log.error("Redis cache write failed: {}", e.getMessage());
        }
    }

    public void evict(String key) {
        evictionCount.incrementAndGet();

        localCache.remove(key);

        try {
            redisTemplate.delete(formatRedisKey(key));
                    } catch (Exception e) {
            log.error("Redis cache eviction failed: {}", e.getMessage());
        }
    }

    public void evictByPattern(String globPattern) {
        String regexPattern = globToRegex(globPattern);
        localCache.entrySet().removeIf(entry ->
            entry.getKey().matches(regexPattern)
        );

        try {
            var matchedKeys = new java.util.ArrayList<String>();
            try (var cursor = redisTemplate.scan(
                    org.springframework.data.redis.core.ScanOptions.scanOptions()
                        .match(formatRedisKey(globPattern))
                        .count(100)
                        .build())) {
                while (cursor.hasNext()) {
                    matchedKeys.add((String) cursor.next());
                }
            }
            if (!matchedKeys.isEmpty()) {
                redisTemplate.delete(matchedKeys);
                evictionCount.addAndGet(matchedKeys.size());
            }
        } catch (Exception e) {
            log.error("Redis pattern cache eviction failed: {}", e.getMessage());
        }
    }

    private String globToRegex(String glob) {
        StringBuilder regex = new StringBuilder();
        for (char c : glob.toCharArray()) {
            switch (c) {
                case '*' -> regex.append(".*");
                case '?' -> regex.append(".");
                case '.' -> regex.append("\\.");
                default -> regex.append(c);
            }
        }
        return regex.toString();
    }

    public void clear() {
        localCache.clear();

        try {
            var keysToDelete = new java.util.ArrayList<String>();
            try (var cursor = redisTemplate.scan(
                    org.springframework.data.redis.core.ScanOptions.scanOptions()
                        .match(formatRedisKey("*"))
                        .count(100)
                        .build())) {
                while (cursor.hasNext()) {
                    keysToDelete.add((String) cursor.next());
                }
            }
            if (!keysToDelete.isEmpty()) {
                redisTemplate.delete(keysToDelete);
            }
        } catch (Exception e) {
            log.error("Redis cache clear failed: {}", e.getMessage());
        }
    }

    public int size() {
        return localCache.size();
    }

    public double getHitRate() {
        long total = hitCount.get() + missCount.get();
        return total > 0 ? (double) hitCount.get() / total : 0.0;
    }

    public CacheStatistics getStatistics() {
        return CacheStatistics.builder()
            .hitCount(hitCount.get())
            .missCount(missCount.get())
            .putCount(putCount.get())
            .evictionCount(evictionCount.get())
            .hitRate(getHitRate())
            .localCacheSize(localCache.size())
            .build();
    }

    public void resetStatistics() {
        hitCount.set(0);
        missCount.set(0);
        putCount.set(0);
        evictionCount.set(0);
            }

    private void putToLocalCache(String key, ToolExecutor.ToolResult value) {
        
        if (localCache.size() >= toolProperties.getCache().getLocalMaxSize()) {
            evictOldestFromLocalCache();
        }
        
        localCache.put(key, new CacheEntry(value, System.currentTimeMillis() + (toolProperties.getCache().getDefaultTtl() * 1000L)));
    }

    private void evictOldestFromLocalCache() {
        localCache.entrySet().stream()
            .min((e1, e2) -> Long.compare(e1.getValue().getExpireTime(), e2.getValue().getExpireTime()))
            .ifPresent(entry -> {
                localCache.remove(entry.getKey());
                evictionCount.incrementAndGet();
                            });
    }

    private String formatRedisKey(String key) {
        return "tool:cache:" + key;
    }

    private static class CacheEntry {
        private final ToolExecutor.ToolResult value;
        private final long expireTime;
        
        public CacheEntry(ToolExecutor.ToolResult value, long expireTime) {
            this.value = value;
            this.expireTime = expireTime;
        }
        
        public ToolExecutor.ToolResult getValue() {
            return value;
        }
        
        public long getExpireTime() {
            return expireTime;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > expireTime;
        }
    }

    @lombok.Builder
    @lombok.Data
    public static class CacheStatistics {
        private long hitCount;
        private long missCount;
        private long putCount;
        private long evictionCount;
        private double hitRate;
        private int localCacheSize;
    }
}