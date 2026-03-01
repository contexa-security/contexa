package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;


@Slf4j
@RequiredArgsConstructor
public class LocalContexaCacheService implements ContexaCacheService {

    private final ContexaCacheProperties properties;
    private final ObjectMapper objectMapper;

    private final ConcurrentHashMap<String, Cache<String, String>> domainCaches = new ConcurrentHashMap<>();
    private Cache<String, String> defaultLocalCache;

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


    private Cache<String, String> getOrCreateDomainCache(String domain) {
        if (domain == null || domain.isEmpty()) {
            return defaultLocalCache;
        }

        return domainCaches.computeIfAbsent(domain, d -> {
            int ttl = getLocalTtl(d);
            return buildLocalCache(ttl);
        });
    }


    private Cache<String, String> buildLocalCache(int ttlSeconds) {
        return Caffeine.newBuilder()
                .maximumSize(properties.getLocal().getMaxSize())
                .expireAfterWrite(ttlSeconds, TimeUnit.SECONDS)
                .recordStats()
                .build();
    }


    private int getLocalTtl(String domain) {
        if (domain == null) {
            return properties.getLocal().getDefaultTtlSeconds();
        }

        ContexaCacheProperties.DomainConfig domains = properties.getDomains();
        return switch (domain.toLowerCase()) {
            case "users" -> domains.getUsers().getLocalTtlSeconds();
            case "roles" -> domains.getRoles().getLocalTtlSeconds();
            case "permissions" -> domains.getPermissions().getLocalTtlSeconds();
            case "groups" -> domains.getGroups().getLocalTtlSeconds();
            case "policies" -> domains.getPolicies().getLocalTtlSeconds();
            case "soar" -> domains.getSoar().getLocalTtlSeconds();
            case "hcad" -> domains.getHcad().getLocalTtlSeconds();
            default -> properties.getLocal().getDefaultTtlSeconds();
        };
    }
}
