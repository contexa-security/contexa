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
package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

import java.util.function.Supplier;


@Slf4j
public class LocalContexaCacheService extends AbstractContexaCacheService {

    public LocalContexaCacheService(ContexaCacheProperties properties, ObjectMapper objectMapper) {
        super(properties, objectMapper);
    }

    @PostConstruct
    public void init() {
        defaultLocalCache = buildLocalCache(properties.getLocal().getDefaultTtlSeconds());
    }


    @Override
    public <T> T get(String key, Supplier<T> loader, TypeReference<T> typeRef, String domain) {
        Cache<String, String> localCache = getOrCreateDomainCache(domain);
        String cachedJson = localCache.getIfPresent(key);
        if (cachedJson != null) {
            try {
                return objectMapper.readValue(cachedJson, typeRef);
            } catch (JsonProcessingException e) {
                log.error("Local cache deserialization failed: {}", key, e);
                localCache.invalidate(key);
            }
        }

        T value = loader.get();
        if (value != null) {
            put(key, value, domain);
        }
        return value;
    }


    @Override
    public <T> void put(String key, T value, String domain) {
        try {
            String json = objectMapper.writeValueAsString(value);
            Cache<String, String> localCache = getOrCreateDomainCache(domain);
            localCache.put(key, json);
        } catch (JsonProcessingException e) {
            log.error("Local cache serialization failed: {}", key, e);
        }
    }


    @Override
    public void invalidate(String key) {
        if (key.contains("*")) {
            String pattern = key.replace("*", "");
            domainCaches.values().forEach(cache -> {
                cache.asMap().keySet().stream()
                        .filter(k -> k.startsWith(pattern))
                        .forEach(cache::invalidate);
            });
            if (defaultLocalCache != null) {
                defaultLocalCache.asMap().keySet().stream()
                        .filter(k -> k.startsWith(pattern))
                        .forEach(defaultLocalCache::invalidate);
            }
        } else {
            domainCaches.values().forEach(cache -> cache.invalidate(key));
            if (defaultLocalCache != null) {
                defaultLocalCache.invalidate(key);
            }
        }
    }


    @Override
    public void invalidateAll() {
        domainCaches.values().forEach(Cache::invalidateAll);
        if (defaultLocalCache != null) {
            defaultLocalCache.invalidateAll();
        }
    }


    @Override
    public void invalidateLocalOnly(String key) {
        invalidate(key);
    }


    @Override
    public ContexaCacheProperties.CacheType getCacheType() {
        return ContexaCacheProperties.CacheType.LOCAL;
    }
}
