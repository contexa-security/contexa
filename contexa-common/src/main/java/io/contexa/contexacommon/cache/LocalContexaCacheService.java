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
