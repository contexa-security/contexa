package io.contexa.contexacore.hcad.trigger.store;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryAnalysisTriggerStateRepository implements AnalysisTriggerStateRepository {

    private final ConcurrentHashMap<String, Instant> negativeCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> cooldownCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> inFlightCache = new ConcurrentHashMap<>();

    @Override
    public boolean isNegativeCached(String baseKey) {
        return isActive(negativeCache, baseKey);
    }

    @Override
    public void markNegative(String baseKey, Duration ttl) {
        if (baseKey != null && ttl != null && !ttl.isZero() && !ttl.isNegative()) {
            negativeCache.put(baseKey, Instant.now().plus(ttl));
        }
    }

    @Override
    public boolean isCoolingDown(String dedupKey) {
        return isActive(cooldownCache, dedupKey);
    }

    @Override
    public boolean isInFlight(String dedupKey) {
        return isActive(inFlightCache, dedupKey);
    }
    @Override
    public synchronized boolean tryAcquireInFlight(String dedupKey, Duration ttl) {
        if (dedupKey == null || ttl == null || ttl.isZero() || ttl.isNegative()) {
            return false;
        }
        if (isActive(inFlightCache, dedupKey)) {
            return false;
        }
        inFlightCache.put(dedupKey, Instant.now().plus(ttl));
        return true;
    }

    @Override
    public void markCooldown(String dedupKey, Duration ttl) {
        if (dedupKey != null && ttl != null && !ttl.isZero() && !ttl.isNegative()) {
            cooldownCache.put(dedupKey, Instant.now().plus(ttl));
        }
    }

    @Override
    public void releaseInFlight(String dedupKey) {
        if (dedupKey != null) {
            inFlightCache.remove(dedupKey);
        }
    }

    private boolean isActive(ConcurrentHashMap<String, Instant> store, String key) {
        if (key == null) {
            return false;
        }
        Instant expiresAt = store.get(key);
        if (expiresAt == null) {
            return false;
        }
        if (Instant.now().isAfter(expiresAt)) {
            store.remove(key, expiresAt);
            return false;
        }
        return true;
    }
}
