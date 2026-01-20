package io.contexa.contexacoreenterprise.mcp.cache;

import io.contexa.contexacoreenterprise.mcp.tool.execution.ToolExecutor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;


@Slf4j
@RequiredArgsConstructor
public class ToolResultCache {
    
    private final RedisTemplate<String, Object> redisTemplate;
    
    @Value("${tool.cache.enabled:true}")
    private boolean cacheEnabled;
    
    @Value("${tool.cache.local-max-size:1000}")
    private int localMaxSize;
    
    @Value("${tool.cache.default-ttl:300}")
    private long defaultTtlSeconds;
    
    
    private final Map<String, CacheEntry> localCache = new ConcurrentHashMap<>();
    
    
    private final AtomicLong hitCount = new AtomicLong(0);
    private final AtomicLong missCount = new AtomicLong(0);
    private final AtomicLong putCount = new AtomicLong(0);
    private final AtomicLong evictionCount = new AtomicLong(0);
    
    
    public ToolExecutor.ToolResult get(String key) {
        if (!cacheEnabled) {
            return null;
        }
        
        
        CacheEntry localEntry = localCache.get(key);
        if (localEntry != null && !localEntry.isExpired()) {
            hitCount.incrementAndGet();
            log.trace("L1 캐시 히트: {}", key);
            return localEntry.getValue();
        }
        
        
        try {
            Object cached = redisTemplate.opsForValue().get(formatRedisKey(key));
            if (cached instanceof ToolExecutor.ToolResult) {
                hitCount.incrementAndGet();
                log.trace("L2 캐시 히트: {}", key);
                
                
                putToLocalCache(key, (ToolExecutor.ToolResult) cached);
                
                return (ToolExecutor.ToolResult) cached;
            }
        } catch (Exception e) {
            log.warn("Redis 캐시 읽기 실패: {}", e.getMessage());
        }
        
        missCount.incrementAndGet();
        log.trace("캐시 미스: {}", key);
        return null;
    }
    
    
    public Optional<ToolExecutor.ToolResult> getOptional(String key) {
        return Optional.ofNullable(get(key));
    }
    
    
    public void put(String key, ToolExecutor.ToolResult value) {
        put(key, value, Duration.ofSeconds(defaultTtlSeconds));
    }
    
    
    public void put(String key, ToolExecutor.ToolResult value, Duration ttl) {
        if (!cacheEnabled || value == null) {
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
            log.trace("캐시 저장: key={}, ttl={}", key, ttl);
        } catch (Exception e) {
            log.warn("Redis 캐시 저장 실패: {}", e.getMessage());
        }
    }
    
    
    public void evict(String key) {
        evictionCount.incrementAndGet();
        
        
        localCache.remove(key);
        
        
        try {
            redisTemplate.delete(formatRedisKey(key));
            log.trace("캐시 제거: {}", key);
        } catch (Exception e) {
            log.warn("Redis 캐시 제거 실패: {}", e.getMessage());
        }
    }
    
    
    public void evictByPattern(String pattern) {
        
        localCache.entrySet().removeIf(entry -> 
            entry.getKey().matches(pattern)
        );
        
        
        try {
            var keys = redisTemplate.keys(formatRedisKey(pattern));
            if (keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
                evictionCount.addAndGet(keys.size());
                log.debug("패턴으로 캐시 제거: pattern={}, count={}", pattern, keys.size());
            }
        } catch (Exception e) {
            log.warn("Redis 패턴 캐시 제거 실패: {}", e.getMessage());
        }
    }
    
    
    public void clear() {
        int localSize = localCache.size();
        localCache.clear();
        
        try {
            var keys = redisTemplate.keys(formatRedisKey("*"));
            if (keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
                log.info("캐시 클리어: local={}, redis={}", localSize, keys.size());
            }
        } catch (Exception e) {
            log.warn("Redis 캐시 클리어 실패: {}", e.getMessage());
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
        log.info("캐시 통계 리셋");
    }
    
    
    
    
    private void putToLocalCache(String key, ToolExecutor.ToolResult value) {
        
        if (localCache.size() >= localMaxSize) {
            evictOldestFromLocalCache();
        }
        
        localCache.put(key, new CacheEntry(value, System.currentTimeMillis() + (defaultTtlSeconds * 1000)));
    }
    
    
    private void evictOldestFromLocalCache() {
        localCache.entrySet().stream()
            .min((e1, e2) -> Long.compare(e1.getValue().getExpireTime(), e2.getValue().getExpireTime()))
            .ifPresent(entry -> {
                localCache.remove(entry.getKey());
                evictionCount.incrementAndGet();
                log.trace("로컬 캐시 LRU 제거: {}", entry.getKey());
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