package io.contexa.contexacore.hcad.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HCAD 기준선 캐시 관리 서비스
 *
 * 기준선 벡터의 메모리 캐시 및 Redis 저장소 관리:
 * - 2단계 캐시 (메모리 + Redis)
 * - LRU 방식 캐시 제거
 * - TTL 기반 만료 관리
 * - 캐시 히트/미스 통계
 */
@Slf4j
@RequiredArgsConstructor
public class HCADBaselineCacheService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final HCADVectorIntegrationService hcadVectorService;

    @Value("${hcad.cache.max-size:100000}")
    private int maxCacheSize;

    @Value("${hcad.cache.ttl-ms:300000}")
    private long cacheTtlMs;

    @Value("${hcad.cache.local.ttl-minutes:10}")
    private int localCacheTtlMinutes;

    // Caffeine 로컬 캐시 (Hot Path 최적화 - <1ms 응답)
    private Cache<String, BaselineVector> localCache;

    // 레거시 메모리 캐시 (하위 호환성 유지, Caffeine으로 마이그레이션 예정)
    private final ConcurrentHashMap<String, CachedBaseline> baselineCache = new ConcurrentHashMap<>();

    @Getter
    private final AtomicLong cacheHits = new AtomicLong();

    @Getter
    private final AtomicLong cacheMisses = new AtomicLong();

    @PostConstruct
    public void initializeLocalCache() {
        this.localCache = Caffeine.newBuilder()
            .maximumSize(maxCacheSize)
            .expireAfterWrite(Duration.ofMinutes(localCacheTtlMinutes))
            .recordStats()
            .build();

        log.info("[HCAD-Cache] Caffeine local cache initialized - maxSize: {}, TTL: {} minutes",
            maxCacheSize, localCacheTtlMinutes);
    }

    /**
     * 기준선 벡터 조회 (3-Tier 캐시: Caffeine → Legacy Memory → Redis)
     *
     * 성능 최적화:
     * - Tier 1 (Caffeine): <1ms (Hot Path 최적화)
     * - Tier 2 (Legacy): ~2ms (하위 호환성)
     * - Tier 3 (Redis): 5-10ms (분산 캐시)
     *
     * @param userId 사용자 ID
     * @return 기준선 벡터
     */
    public BaselineVector getBaseline(String userId) {
        try {
            // 1. Caffeine 로컬 캐시 확인 (<1ms - Hot Path 최적화)
            BaselineVector fromLocal = localCache.getIfPresent(userId);
            if (fromLocal != null) {
                cacheHits.incrementAndGet();
                if (log.isDebugEnabled()) {
                    log.debug("[HCAD-Cache] Caffeine hit: userId={}", userId);
                }
                return fromLocal;
            }

            // 2. 레거시 메모리 캐시 확인 (~2ms - 하위 호환성)
            CachedBaseline legacyCached = baselineCache.get(userId);
            if (legacyCached != null && !legacyCached.isExpired()) {
                BaselineVector baseline = legacyCached.getBaseline();

                // Caffeine 캐시에도 저장 (다음 요청부터 <1ms)
                localCache.put(userId, baseline);

                cacheHits.incrementAndGet();
                if (log.isDebugEnabled()) {
                    log.debug("[HCAD-Cache] Legacy cache hit: userId={}", userId);
                }
                return baseline;
            }

            // 3. Redis 에서 조회 (5-10ms)
            cacheMisses.incrementAndGet();
            BaselineVector baseline = loadFromRedis(userId);

            // 4. 모든 캐시 레이어에 저장
            localCache.put(userId, baseline);

            if (baselineCache.size() >= maxCacheSize) {
                evictOldestCacheEntry();
            }
            baselineCache.put(userId, new CachedBaseline(baseline, cacheTtlMs));

            if (log.isDebugEnabled()) {
                log.debug("[HCAD-Cache] Redis load: userId={}, stored in all cache tiers", userId);
            }

            return baseline;
        } catch (Exception e) {
            log.error("[HCAD] 기준선 조회 실패: userId={}", userId, e);
            return createEmptyBaseline(userId);
        }
    }

    /**
     * Redis에서 기준선 조회
     * 개선: HCADRedisKeys 사용
     *
     * @param userId 사용자 ID
     * @return 기준선 벡터
     */
    private BaselineVector loadFromRedis(String userId) {
        try {
            String key = HCADRedisKeys.baselineVector(userId);
            BaselineVector baseline = (BaselineVector) redisTemplate.opsForValue().get(key);

            if (baseline == null) {
                baseline = createEmptyBaseline(userId);
            }

            // Layer1/2/3 통합 피드백 적용 (가중치: Layer3 70% + Layer2 20% + Layer1 10%)
            if (hcadVectorService != null) {
                hcadVectorService.applyAllLayersFeedbackToBaseline(baseline, userId);
            }

            return baseline;
        } catch (Exception e) {
            log.error("[HCAD] Redis 기준선 조회 실패: userId={}", userId, e);
            return createEmptyBaseline(userId);
        }
    }

    /**
     * 빈 기준선 생성
     *
     * @param userId 사용자 ID
     * @return 초기화된 기준선 벡터
     */
    public BaselineVector createEmptyBaseline(String userId) {
        return BaselineVector.builder()
            .userId(userId)
            .confidence(0.0)
            .updateCount(0L)
            .lastUpdated(Instant.now())
            .build();
    }

    /**
     * LRU 방식으로 가장 오래된 캐시 항목 제거
     */
    private void evictOldestCacheEntry() {
        // 간단한 LRU - 만료된 항목부터 제거
        baselineCache.entrySet().removeIf(entry -> entry.getValue().isExpired());

        // 여전히 가득 찬 경우 하나 제거
        if (baselineCache.size() >= maxCacheSize) {
            String firstKey = baselineCache.keys().nextElement();
            baselineCache.remove(firstKey);
        }
    }

    /**
     * Caffeine 캐시 통계 조회
     *
     * 모니터링 및 성능 분석용
     *
     * @return 캐시 통계
     */
    public CacheStats getCaffeineStats() {
        return localCache.stats();
    }

    /**
     * 캐시 히트율 조회
     *
     * @return 히트율 (0.0 ~ 1.0)
     */
    public double getCacheHitRate() {
        CacheStats stats = localCache.stats();
        long totalRequests = stats.requestCount();
        if (totalRequests == 0) {
            return 0.0;
        }
        return (double) stats.hitCount() / totalRequests;
    }

    /**
     * 특정 사용자의 캐시 무효화 (v3.1)
     *
     * Redis에 기준선이 업데이트된 후 로컬 캐시를 무효화하여
     * 캐시 일관성을 보장합니다.
     *
     * @param userId 사용자 ID
     */
    public void invalidateCache(String userId) {
        if (userId == null) {
            return;
        }

        // Caffeine 로컬 캐시 무효화
        localCache.invalidate(userId);

        // 레거시 메모리 캐시 무효화
        baselineCache.remove(userId);

        if (log.isDebugEnabled()) {
            log.debug("[HCAD-Cache] Cache invalidated for userId: {}", userId);
        }
    }

    /**
     * 캐시 통계 로깅 (정기 모니터링용)
     */
    public void logCacheStatistics() {
        CacheStats stats = localCache.stats();
        log.info("[HCAD-Cache] Caffeine stats - hitRate: {:.2f}%, hits: {}, misses: {}, evictions: {}, size: {}",
            getCacheHitRate() * 100,
            stats.hitCount(),
            stats.missCount(),
            stats.evictionCount(),
            localCache.estimatedSize());
    }

    /**
     * TTL을 가진 캐시 항목
     */
    private static class CachedBaseline {
        private final BaselineVector baseline;
        private final long expiryTime;

        public CachedBaseline(BaselineVector baseline, long ttlMs) {
            this.baseline = baseline;
            this.expiryTime = System.currentTimeMillis() + ttlMs;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }

        public BaselineVector getBaseline() {
            return baseline;
        }
    }
}
