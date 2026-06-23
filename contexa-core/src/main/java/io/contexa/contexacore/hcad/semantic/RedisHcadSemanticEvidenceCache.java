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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.properties.HcadProperties;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public class RedisHcadSemanticEvidenceCache implements HcadSemanticEvidenceCache {

    private final StringRedisTemplate stringRedisTemplate;
    private final ObjectMapper objectMapper;
    private final String namespace;

    public RedisHcadSemanticEvidenceCache(
            StringRedisTemplate stringRedisTemplate,
            ObjectMapper objectMapper,
            HcadProperties hcadProperties) {
        this.stringRedisTemplate = stringRedisTemplate;
        this.objectMapper = objectMapper;
        this.namespace = hcadProperties.getSemanticEvidence().getRedisKeyPrefix();
    }

    @Override
    public Optional<HcadSemanticEvidenceEntry> get(HcadSemanticEvidenceKey key) {
        if (key == null) {
            return Optional.empty();
        }
        if (isSourceAbsent(key)) {
            return Optional.of(sourceAbsentEntry(key));
        }
        Optional<HcadSemanticEvidenceEntry> exact = readEntry(
                HcadSemanticEvidenceKeyFactory.cacheKey(namespace, key));
        if (exact.isPresent()) {
            return exact;
        }
        Optional<HcadSemanticEvidenceEntry> compatible = readEntry(
                HcadSemanticEvidenceKeyFactory.compatibilityKey(namespace, key));
        if (compatible.isPresent()) {
            return Optional.of(compatible.get().forRequestedKey(key));
        }
        return Optional.empty();
    }

    @Override
    public void put(HcadSemanticEvidenceEntry entry, Duration ttl) {
        if (entry == null || entry.key() == null || !positive(ttl)) {
            return;
        }
        try {
            stringRedisTemplate.opsForValue().set(
                    HcadSemanticEvidenceKeyFactory.cacheKey(namespace, entry.key()),
                    objectMapper.writeValueAsString(entry),
                    ttl);
            stringRedisTemplate.opsForValue().set(
                    HcadSemanticEvidenceKeyFactory.compatibilityKey(namespace, entry.key()),
                    objectMapper.writeValueAsString(entry),
                    ttl);
        } catch (JsonProcessingException ignored) {
        }
    }

    @Override
    public void putSourceAbsent(HcadSemanticEvidenceKey key, Duration ttl) {
        if (key == null || !positive(ttl)) {
            return;
        }
        stringRedisTemplate.opsForValue().set(
                HcadSemanticEvidenceKeyFactory.negativeCacheKey(namespace, key),
                "1",
                ttl);
    }

    @Override
    public boolean isSourceAbsent(HcadSemanticEvidenceKey key) {
        return key != null
                && Boolean.TRUE.equals(stringRedisTemplate.hasKey(
                        HcadSemanticEvidenceKeyFactory.negativeCacheKey(namespace, key)));
    }

    @Override
    public void invalidate(HcadSemanticEvidenceKey key) {
        if (key == null) {
            return;
        }
        stringRedisTemplate.delete(List.of(
                HcadSemanticEvidenceKeyFactory.cacheKey(namespace, key),
                HcadSemanticEvidenceKeyFactory.compatibilityKey(namespace, key),
                HcadSemanticEvidenceKeyFactory.negativeCacheKey(namespace, key)));
    }

    @Override
    public HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider provider() {
        return HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.REDIS;
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
                List.of("SOURCE_ABSENT"),
                Instant.now(),
                null);
    }

    private Optional<HcadSemanticEvidenceEntry> readEntry(String cacheKey) {
        String value = stringRedisTemplate.opsForValue().get(cacheKey);
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(objectMapper.readValue(value, HcadSemanticEvidenceEntry.class));
        } catch (JsonProcessingException ex) {
            return Optional.empty();
        }
    }

    private boolean positive(Duration ttl) {
        return ttl != null && !ttl.isZero() && !ttl.isNegative();
    }
}
