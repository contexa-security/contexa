package io.contexa.contexacore.autonomous.repository;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryProtectableRapidReentryRepository implements ProtectableRapidReentryRepository {

    private final ConcurrentHashMap<String, Instant> reentryWindows = new ConcurrentHashMap<>();

    @Override
    public boolean tryAcquire(String userId, String contextBindingHash, String resourceKey, Duration window) {
        if (isInvalid(userId) || isInvalid(contextBindingHash) || isInvalid(resourceKey) || window == null) {
            return true;
        }

        Instant now = Instant.now();
        Instant expiresAt = now.plus(window);
        String key = buildKey(userId, contextBindingHash, resourceKey);

        while (true) {
            Instant existing = reentryWindows.get(key);
            if (existing != null) {
                if (existing.isAfter(now)) {
                    return false;
                }
                if (!reentryWindows.remove(key, existing)) {
                    continue;
                }
            }

            Instant previous = reentryWindows.putIfAbsent(key, expiresAt);
            if (previous == null) {
                return true;
            }
            if (previous.isAfter(now)) {
                return false;
            }
            reentryWindows.remove(key, previous);
        }
    }

    private String buildKey(String userId, String contextBindingHash, String resourceKey) {
        return userId + ":" + contextBindingHash + ":" + resourceKey;
    }

    private boolean isInvalid(String value) {
        return value == null || value.isBlank();
    }
}
