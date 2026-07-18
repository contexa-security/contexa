package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

final class OfficialRunPackageDetailCache {

    private static final Duration TTL = Duration.ofSeconds(30);
    private static final int MAX_SIZE = 128;

    private final ConcurrentHashMap<String, CachedDetail> entries = new ConcurrentHashMap<>();

    String key(String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(packageId) || !StringUtils.hasText(aggregateRunId)) {
            return null;
        }
        return packageId.trim() + "\n" + aggregateRunId.trim();
    }

    OfficialRunPackageDetail get(String key) {
        if (!StringUtils.hasText(key)) {
            return null;
        }
        CachedDetail cached = entries.get(key);
        if (cached == null) {
            return null;
        }
        if (System.nanoTime() > cached.expiresAtNanos()) {
            entries.remove(key, cached);
            return null;
        }
        return cached.detail();
    }

    void put(String key, OfficialRunPackageDetail detail) {
        if (!StringUtils.hasText(key) || detail == null) {
            return;
        }
        prune();
        entries.put(key, new CachedDetail(detail, System.nanoTime() + TTL.toNanos()));
    }

    private void prune() {
        if (entries.size() < MAX_SIZE) {
            return;
        }
        long now = System.nanoTime();
        entries.entrySet().removeIf(entry -> entry.getValue() == null || now > entry.getValue().expiresAtNanos());
        if (entries.size() >= MAX_SIZE) {
            entries.clear();
        }
    }

    private record CachedDetail(OfficialRunPackageDetail detail, long expiresAtNanos) {
    }
}