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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HcadSemanticEvidenceCacheTest {

    @Test
    @DisplayName("local mode should select Caffeine semantic evidence cache")
    void factory_localMode_shouldSelectCaffeine() {
        HcadSemanticEvidenceCache cache = HcadSemanticEvidenceCacheFactory.create(
                "local",
                new HcadProperties(),
                null,
                objectMapper());

        assertThat(cache).isInstanceOf(CaffeineHcadSemanticEvidenceCache.class);
        assertThat(cache.provider()).isEqualTo(HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.CAFFEINE);
    }

    @Test
    @DisplayName("distributed mode should select Redis semantic evidence cache")
    void factory_distributedModeWithRedis_shouldSelectRedis() {
        HcadSemanticEvidenceCache cache = HcadSemanticEvidenceCacheFactory.create(
                "distributed",
                new HcadProperties(),
                mock(StringRedisTemplate.class),
                objectMapper());

        assertThat(cache).isInstanceOf(RedisHcadSemanticEvidenceCache.class);
        assertThat(cache.provider()).isEqualTo(HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.REDIS);
    }

    @Test
    @DisplayName("distributed mode without Redis should not silently fall back to Caffeine")
    void factory_distributedModeWithoutRedis_shouldDisable() {
        HcadSemanticEvidenceCache cache = HcadSemanticEvidenceCacheFactory.create(
                "distributed",
                new HcadProperties(),
                null,
                objectMapper());

        assertThat(cache).isInstanceOf(DisabledHcadSemanticEvidenceCache.class);
        assertThat(((DisabledHcadSemanticEvidenceCache) cache).reason())
                .isEqualTo("REDIS_REQUIRED_FOR_DISTRIBUTED_SEMANTIC_EVIDENCE");
    }

    @Test
    @DisplayName("provider override should not allow Caffeine in distributed mode")
    void factory_distributedModeWithCaffeineOverride_shouldDisable() {
        HcadProperties properties = new HcadProperties();
        properties.getSemanticEvidence().setProvider(
                HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.CAFFEINE);

        HcadSemanticEvidenceCache cache = HcadSemanticEvidenceCacheFactory.create(
                "distributed",
                properties,
                mock(StringRedisTemplate.class),
                objectMapper());

        assertThat(cache).isInstanceOf(DisabledHcadSemanticEvidenceCache.class);
        assertThat(((DisabledHcadSemanticEvidenceCache) cache).reason())
                .isEqualTo("CAFFEINE_NOT_ALLOWED_FOR_DISTRIBUTED_SEMANTIC_EVIDENCE");
    }

    @Test
    @DisplayName("provider override should not allow Redis in local mode")
    void factory_localModeWithRedisOverride_shouldDisable() {
        HcadProperties properties = new HcadProperties();
        properties.getSemanticEvidence().setProvider(
                HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.REDIS);

        HcadSemanticEvidenceCache cache = HcadSemanticEvidenceCacheFactory.create(
                "local",
                properties,
                mock(StringRedisTemplate.class),
                objectMapper());

        assertThat(cache).isInstanceOf(DisabledHcadSemanticEvidenceCache.class);
        assertThat(((DisabledHcadSemanticEvidenceCache) cache).reason())
                .isEqualTo("REDIS_NOT_ALLOWED_FOR_LOCAL_SEMANTIC_EVIDENCE");
    }

    @Test
    @DisplayName("Caffeine cache should store evidence and source-absent negative entries separately")
    void caffeineCache_shouldStoreEvidenceAndSourceAbsentEntries() {
        CaffeineHcadSemanticEvidenceCache cache = new CaffeineHcadSemanticEvidenceCache(new HcadProperties());
        HcadSemanticEvidenceEntry entry = entry(HcadSemanticEvidenceCacheStatus.HIT);

        cache.put(entry, Duration.ofMinutes(5));

        assertThat(cache.get(entry.key()))
                .hasValueSatisfying(cached -> assertThat(cached.status()).isEqualTo(HcadSemanticEvidenceCacheStatus.HIT));

        cache.invalidate(entry.key());
        cache.putSourceAbsent(entry.key(), Duration.ofMinutes(5));

        assertThat(cache.isSourceAbsent(entry.key())).isTrue();
        assertThat(cache.get(entry.key()))
                .hasValueSatisfying(cached -> assertThat(cached.status())
                        .isEqualTo(HcadSemanticEvidenceCacheStatus.NEGATIVE_CACHE_HIT));
    }

    @Test
    @DisplayName("Caffeine cache should expose version and dimension mismatch through compatibility keys")
    void caffeineCache_shouldExposeVersionAndDimensionMismatch() {
        CaffeineHcadSemanticEvidenceCache cache = new CaffeineHcadSemanticEvidenceCache(new HcadProperties());
        HcadSemanticEvidenceEntry entry = entry(HcadSemanticEvidenceCacheStatus.HIT);
        cache.put(entry, Duration.ofMinutes(5));
        HcadSemanticEvidenceKey versionChanged = HcadSemanticEvidenceKey.riskRequestSimilarity(
                "tenant-1",
                "alice",
                "orders.write",
                "policy-v2",
                "prompt-v1",
                "bge-small",
                384,
                "semantic-v1");
        HcadSemanticEvidenceKey dimensionChanged = HcadSemanticEvidenceKey.riskRequestSimilarity(
                "tenant-1",
                "alice",
                "orders.write",
                "policy-v1",
                "prompt-v1",
                "bge-small",
                768,
                "semantic-v1");

        assertThat(cache.get(versionChanged))
                .hasValueSatisfying(cached -> {
                    assertThat(cached.status()).isEqualTo(HcadSemanticEvidenceCacheStatus.VERSION_MISMATCH);
                    assertThat(cached.usableForScoring()).isFalse();
                    assertThat(cached.evidenceGapCodes()).contains("VERSION_MISMATCH");
                });
        assertThat(cache.get(dimensionChanged))
                .hasValueSatisfying(cached -> {
                    assertThat(cached.status()).isEqualTo(HcadSemanticEvidenceCacheStatus.DIMENSION_MISMATCH);
                    assertThat(cached.usableForScoring()).isFalse();
                    assertThat(cached.evidenceGapCodes()).contains("DIMENSION_MISMATCH");
                });
    }

    @Test
    @DisplayName("Redis cache should store serialized evidence and source-absent key with TTL")
    @SuppressWarnings("unchecked")
    void redisCache_shouldStoreEvidenceAndSourceAbsentEntries() throws Exception {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        ValueOperations<String, String> valueOperations = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.hasKey(any(String.class))).thenReturn(false);
        ObjectMapper objectMapper = objectMapper();
        HcadProperties properties = new HcadProperties();
        RedisHcadSemanticEvidenceCache cache =
                new RedisHcadSemanticEvidenceCache(redisTemplate, objectMapper, properties);
        HcadSemanticEvidenceEntry entry = entry(HcadSemanticEvidenceCacheStatus.HIT);
        String key = HcadSemanticEvidenceKeyFactory.cacheKey(
                properties.getSemanticEvidence().getRedisKeyPrefix(),
                entry.key());

        cache.put(entry, Duration.ofMinutes(5));

        verify(valueOperations).set(eq(key), any(String.class), eq(Duration.ofMinutes(5)));
        verify(valueOperations).set(
                eq(HcadSemanticEvidenceKeyFactory.compatibilityKey(
                        properties.getSemanticEvidence().getRedisKeyPrefix(),
                        entry.key())),
                any(String.class),
                eq(Duration.ofMinutes(5)));

        String json = objectMapper.writeValueAsString(entry);
        when(valueOperations.get(key)).thenReturn(json);

        assertThat(cache.get(entry.key()))
                .hasValueSatisfying(cached -> assertThat(cached.status()).isEqualTo(HcadSemanticEvidenceCacheStatus.HIT));

        cache.putSourceAbsent(entry.key(), Duration.ofSeconds(30));
        verify(valueOperations).set(
                eq(HcadSemanticEvidenceKeyFactory.negativeCacheKey(
                        properties.getSemanticEvidence().getRedisKeyPrefix(),
                        entry.key())),
                eq("1"),
                eq(Duration.ofSeconds(30)));
    }

    @Test
    @DisplayName("Redis cache should expose compatible stale evidence as a version mismatch")
    @SuppressWarnings("unchecked")
    void redisCache_shouldExposeCompatibleEvidenceAsVersionMismatch() throws Exception {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        ValueOperations<String, String> valueOperations = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.hasKey(any(String.class))).thenReturn(false);
        ObjectMapper objectMapper = objectMapper();
        HcadProperties properties = new HcadProperties();
        RedisHcadSemanticEvidenceCache cache =
                new RedisHcadSemanticEvidenceCache(redisTemplate, objectMapper, properties);
        HcadSemanticEvidenceEntry entry = entry(HcadSemanticEvidenceCacheStatus.HIT);
        HcadSemanticEvidenceKey requested = HcadSemanticEvidenceKey.riskRequestSimilarity(
                "tenant-1",
                "alice",
                "orders.write",
                "policy-v2",
                "prompt-v1",
                "bge-small",
                384,
                "semantic-v1");
        when(valueOperations.get(HcadSemanticEvidenceKeyFactory.cacheKey(
                properties.getSemanticEvidence().getRedisKeyPrefix(),
                requested))).thenReturn(null);
        when(valueOperations.get(HcadSemanticEvidenceKeyFactory.compatibilityKey(
                properties.getSemanticEvidence().getRedisKeyPrefix(),
                requested))).thenReturn(objectMapper.writeValueAsString(entry));

        assertThat(cache.get(requested))
                .hasValueSatisfying(cached -> {
                    assertThat(cached.status()).isEqualTo(HcadSemanticEvidenceCacheStatus.VERSION_MISMATCH);
                    assertThat(cached.usableForScoring()).isFalse();
                });
    }

    @Test
    @DisplayName("semantic projection should retain non-usable cache status as evidence gaps")
    void projection_shouldRetainNonUsableStatusAsEvidenceGaps() {
        HcadSemanticEvidenceEntry entry = entry(HcadSemanticEvidenceCacheStatus.HIT)
                .withStatus(HcadSemanticEvidenceCacheStatus.DIMENSION_MISMATCH, "DIMENSION_MISMATCH");

        CachedSemanticEvidenceProjection projection = CachedSemanticEvidenceProjection.of(List.of(entry));

        assertThat(projection.hasUsableEvidence()).isFalse();
        assertThat(projection.evidenceGapCodes())
                .contains("DIMENSION_MISMATCH");
    }

    @Test
    @DisplayName("stale semantic evidence should remain visible but not usable for scoring")
    void projection_staleHit_shouldRemainVisibleButNotUsableForScoring() {
        HcadSemanticEvidenceEntry entry = entry(HcadSemanticEvidenceCacheStatus.STALE_HIT);

        CachedSemanticEvidenceProjection projection = CachedSemanticEvidenceProjection.of(List.of(entry));

        assertThat(projection.hasUsableEvidence()).isFalse();
        assertThat(projection.hasFreshHit()).isFalse();
        assertThat(projection.hasStaleHit()).isTrue();
        assertThat(projection.maxSimilarityToRisk()).isZero();
        assertThat(projection.evidenceGapCodes()).contains("STALE_HIT");
        assertThat(projection.snapshot())
                .extracting("semanticEvidenceStaleHit")
                .isEqualTo(true);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> entries =
                (List<Map<String, Object>>) projection.snapshot().get("semanticEvidenceEntries");
        assertThat(entries).singleElement().satisfies(snapshot -> {
            assertThat(snapshot).containsEntry("status", "STALE_HIT");
            assertThat(snapshot).containsEntry("sourceVersion", "source-v1");
            assertThat(snapshot).containsEntry("sampleCount", null);
        });
    }

    private ObjectMapper objectMapper() {
        return new ObjectMapper().findAndRegisterModules();
    }

    private HcadSemanticEvidenceEntry entry(HcadSemanticEvidenceCacheStatus status) {
        return new HcadSemanticEvidenceEntry(
                HcadSemanticEvidenceKey.riskRequestSimilarity(
                        "tenant-1",
                        "alice",
                        "orders.write",
                        "policy-v1",
                        "prompt-v1",
                        "bge-small",
                        384,
                        "semantic-v1"),
                status,
                "source-v1",
                "semantic-v1",
                "bge-small",
                384,
                0.12d,
                0.91d,
                0.72d,
                "{}",
                List.of(),
                Instant.now(),
                Instant.now().plusSeconds(300));
    }
}
