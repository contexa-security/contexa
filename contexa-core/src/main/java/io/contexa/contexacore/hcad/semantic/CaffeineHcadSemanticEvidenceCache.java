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
package io.contexa.contexacore.hcad.semantic;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import io.contexa.contexacore.properties.HcadProperties;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class CaffeineHcadSemanticEvidenceCache implements HcadSemanticEvidenceCache {

    private static final long MAX_TTL_NANOS = TimeUnit.DAYS.toNanos(30L);

    private final Cache<String, TimedEntry> evidenceCache;
    private final Cache<String, Long> sourceAbsentCache;

    public CaffeineHcadSemanticEvidenceCache(HcadProperties hcadProperties) {
        int maxEntries = Math.max(1, hcadProperties.getSemanticEvidence().getMaxCaffeineEntries());
        this.evidenceCache = Caffeine.newBuilder()
                .maximumSize(maxEntries)
                .expireAfter(TIMED_ENTRY_EXPIRY)
                .build();
        this.sourceAbsentCache = Caffeine.newBuilder()
                .maximumSize(maxEntries)
                .expireAfter(REMAINING_NANOS_EXPIRY)
                .build();
    }

    @Override
    public Optional<HcadSemanticEvidenceEntry> get(HcadSemanticEvidenceKey key) {
        if (key == null) {
            return Optional.empty();
        }
        if (isSourceAbsent(key)) {
            return Optional.of(sourceAbsentEntry(key));
        }
        TimedEntry timedEntry = evidenceCache.getIfPresent(HcadSemanticEvidenceKeyFactory.cacheKey(key));
        if (timedEntry != null) {
            return Optional.of(timedEntry.entry());
        }
        TimedEntry compatibleEntry = evidenceCache.getIfPresent(HcadSemanticEvidenceKeyFactory.compatibilityKey(key));
        return compatibleEntry == null
                ? Optional.empty()
                : Optional.of(compatibleEntry.entry().forRequestedKey(key));
    }

    @Override
    public void put(HcadSemanticEvidenceEntry entry, Duration ttl) {
        if (entry == null || entry.key() == null || !positive(ttl)) {
            return;
        }
        evidenceCache.put(
                HcadSemanticEvidenceKeyFactory.cacheKey(entry.key()),
                new TimedEntry(entry, expiresAtNanos(ttl)));
        evidenceCache.put(
                HcadSemanticEvidenceKeyFactory.compatibilityKey(entry.key()),
                new TimedEntry(entry, expiresAtNanos(ttl)));
    }

    @Override
    public void putSourceAbsent(HcadSemanticEvidenceKey key, Duration ttl) {
        if (key == null || !positive(ttl)) {
            return;
        }
        sourceAbsentCache.put(
                HcadSemanticEvidenceKeyFactory.negativeCacheKey(key),
                expiresAtNanos(ttl));
    }

    @Override
    public boolean isSourceAbsent(HcadSemanticEvidenceKey key) {
        return key != null
                && sourceAbsentCache.getIfPresent(HcadSemanticEvidenceKeyFactory.negativeCacheKey(key)) != null;
    }

    @Override
    public void invalidate(HcadSemanticEvidenceKey key) {
        if (key == null) {
            return;
        }
        evidenceCache.invalidate(HcadSemanticEvidenceKeyFactory.cacheKey(key));
        evidenceCache.invalidate(HcadSemanticEvidenceKeyFactory.compatibilityKey(key));
        sourceAbsentCache.invalidate(HcadSemanticEvidenceKeyFactory.negativeCacheKey(key));
    }

    @Override
    public HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider provider() {
        return HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.CAFFEINE;
    }

    private HcadSemanticEvidenceEntry sourceAbsentEntry(HcadSemanticEvidenceKey key) {
        return new HcadSemanticEvidenceEntry(
                key,
                HcadSemanticEvidenceCacheStatus.NEGATIVE_CACHE_HIT,
                null,
                key.evidenceVersion(),
                key.embeddingModel(),
                key.dimension(),
                null,
                null,
                null,
                null,
                java.util.List.of("SOURCE_ABSENT"),
                java.time.Instant.now(),
                null);
    }

    private boolean positive(Duration ttl) {
        return ttl != null && !ttl.isZero() && !ttl.isNegative();
    }

    private long expiresAtNanos(Duration ttl) {
        long ttlNanos = Math.min(ttl.toNanos(), MAX_TTL_NANOS);
        return System.nanoTime() + Math.max(1L, ttlNanos);
    }

    private static final Expiry<String, TimedEntry> TIMED_ENTRY_EXPIRY = new Expiry<>() {
        @Override
        public long expireAfterCreate(String key, TimedEntry value, long currentTimeNanos) {
            return Math.max(1L, value.expiresAtNanos() - currentTimeNanos);
        }

        @Override
        public long expireAfterUpdate(
                String key,
                TimedEntry value,
                long currentTimeNanos,
                long currentDurationNanos) {
            return Math.max(1L, value.expiresAtNanos() - currentTimeNanos);
        }

        @Override
        public long expireAfterRead(
                String key,
                TimedEntry value,
                long currentTimeNanos,
                long currentDurationNanos) {
            return currentDurationNanos;
        }
    };

    private static final Expiry<String, Long> REMAINING_NANOS_EXPIRY = new Expiry<>() {
        @Override
        public long expireAfterCreate(String key, Long expiresAtNanos, long currentTimeNanos) {
            return Math.max(1L, expiresAtNanos - currentTimeNanos);
        }

        @Override
        public long expireAfterUpdate(
                String key,
                Long expiresAtNanos,
                long currentTimeNanos,
                long currentDurationNanos) {
            return Math.max(1L, expiresAtNanos - currentTimeNanos);
        }

        @Override
        public long expireAfterRead(
                String key,
                Long expiresAtNanos,
                long currentTimeNanos,
                long currentDurationNanos) {
            return currentDurationNanos;
        }
    };

    private record TimedEntry(HcadSemanticEvidenceEntry entry, long expiresAtNanos) {
    }
}
