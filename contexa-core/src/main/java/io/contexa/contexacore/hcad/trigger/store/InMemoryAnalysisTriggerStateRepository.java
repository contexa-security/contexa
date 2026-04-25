package io.contexa.contexacore.hcad.trigger.store;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * In-memory analysis trigger state repository backed by Caffeine.
 * Uses variable per-entry TTL via {@link Expiry} so callers can pass arbitrary TTL durations.
 * Background eviction by Caffeine prevents the lazy-cleanup memory leak of the previous
 * ConcurrentHashMap-based implementation, which retained never-revisited expired keys forever.
 */
public class InMemoryAnalysisTriggerStateRepository implements AnalysisTriggerStateRepository {

    private static final long MAX_ENTRIES = 100_000L;
    private static final long MAX_TTL_NANOS = TimeUnit.HOURS.toNanos(1L);

    private final Cache<String, Long> negativeCache = buildExpiringCache();
    private final Cache<String, Long> cooldownCache = buildExpiringCache();
    private final Cache<String, Long> inFlightCache = buildExpiringCache();

    private static Cache<String, Long> buildExpiringCache() {
        return Caffeine.newBuilder()
                .maximumSize(MAX_ENTRIES)
                .expireAfter(REMAINING_NANOS_EXPIRY)
                .build();
    }

    @Override
    public boolean isNegativeCached(String baseKey) {
        return baseKey != null && negativeCache.getIfPresent(baseKey) != null;
    }

    @Override
    public void markNegative(String baseKey, Duration ttl) {
        putWithTtl(negativeCache, baseKey, ttl);
    }

    @Override
    public boolean isCoolingDown(String dedupKey) {
        return dedupKey != null && cooldownCache.getIfPresent(dedupKey) != null;
    }

    @Override
    public boolean isInFlight(String dedupKey) {
        return dedupKey != null && inFlightCache.getIfPresent(dedupKey) != null;
    }

    @Override
    public synchronized boolean tryAcquireInFlight(String dedupKey, Duration ttl) {
        if (dedupKey == null || ttl == null || ttl.isZero() || ttl.isNegative()) {
            return false;
        }
        if (inFlightCache.getIfPresent(dedupKey) != null) {
            return false;
        }
        putWithTtl(inFlightCache, dedupKey, ttl);
        return true;
    }

    @Override
    public void markCooldown(String dedupKey, Duration ttl) {
        putWithTtl(cooldownCache, dedupKey, ttl);
    }

    @Override
    public void releaseInFlight(String dedupKey) {
        if (dedupKey != null) {
            inFlightCache.invalidate(dedupKey);
        }
    }

    private static void putWithTtl(Cache<String, Long> cache, String key, Duration ttl) {
        if (key == null || ttl == null || ttl.isZero() || ttl.isNegative()) {
            return;
        }
        long ttlNanos = Math.min(ttl.toNanos(), MAX_TTL_NANOS);
        long expiresAtNanos = System.nanoTime() + ttlNanos;
        cache.put(key, expiresAtNanos);
    }

    private static final Expiry<String, Long> REMAINING_NANOS_EXPIRY = new Expiry<>() {
        @Override
        public long expireAfterCreate(String key, Long expiresAtNanos, long currentTimeNanos) {
            return Math.max(1L, expiresAtNanos - currentTimeNanos);
        }

        @Override
        public long expireAfterUpdate(String key, Long expiresAtNanos,
                                      long currentTimeNanos, long currentDurationNanos) {
            return Math.max(1L, expiresAtNanos - currentTimeNanos);
        }

        @Override
        public long expireAfterRead(String key, Long expiresAtNanos,
                                    long currentTimeNanos, long currentDurationNanos) {
            return currentDurationNanos;
        }
    };
}
