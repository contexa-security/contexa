package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;


@Slf4j
@RequiredArgsConstructor
public class RedisContexaCacheService implements ContexaCacheService {

    private final ContexaCacheProperties properties;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;


    private final ConcurrentHashMap<String, Cache<String, String>> domainCaches = new ConcurrentHashMap<>();


    private Cache<String, String> defaultLocalCache;

    @PostConstruct
    public void init() {
        if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {

            defaultLocalCache = buildLocalCache(properties.getLocal().getDefaultTtlSeconds());
        }
    }


    @Override
    public <T> T get(String key, Supplier<T> loader, TypeReference<T> typeRef, String domain) {

        if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {
            Cache<String, String> localCache = getOrCreateDomainCache(domain);
            String cachedJson = localCache.getIfPresent(key);
            if (cachedJson != null) {
                try {
                    return objectMapper.readValue(cachedJson, typeRef);
                } catch (JsonProcessingException e) {
                    log.error("L1 cache deserialization failed: {}", key, e);
                    localCache.invalidate(key);
                }
            }
        }


        if (properties.getType() != ContexaCacheProperties.CacheType.LOCAL) {
            String redisKey = properties.getRedis().getKeyPrefix() + key;
            try {
                String redisJson = redisTemplate.opsForValue().get(redisKey);
                if (redisJson != null) {
                    T value = objectMapper.readValue(redisJson, typeRef);

                    if (properties.getType() == ContexaCacheProperties.CacheType.HYBRID) {
                        backfillToL1(key, redisJson, domain);
                    }
                    return value;
                }
            } catch (Exception e) {
                log.error("L2 cache lookup failed: {}", key, e);
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


            if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {
                Cache<String, String> localCache = getOrCreateDomainCache(domain);
                localCache.put(key, json);
            }


            if (properties.getType() != ContexaCacheProperties.CacheType.LOCAL) {
                String redisKey = properties.getRedis().getKeyPrefix() + key;
                int ttlSeconds = getRedisTtl(domain);
                redisTemplate.opsForValue().set(redisKey, json, ttlSeconds, TimeUnit.SECONDS);
            }


        } catch (JsonProcessingException e) {
            log.error("Cache serialization failed: {}", key, e);
        }
    }


    @Override
    public void invalidate(String key) {


        if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {
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


        if (properties.getType() != ContexaCacheProperties.CacheType.LOCAL) {
            String redisPattern = properties.getRedis().getKeyPrefix() + key;
            if (key.contains("*")) {
                Set<String> keys = scanKeys(redisPattern);
                if (!keys.isEmpty()) {
                    redisTemplate.delete(keys);
                }
            } else {
                redisTemplate.delete(redisPattern);
            }
        }


        if (properties.getType() == ContexaCacheProperties.CacheType.HYBRID
                && properties.getPubsub().isEnabled()) {
            publishInvalidationEvent(key);
        }
    }


    @Override
    public void invalidateAll() {


        if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {
            domainCaches.values().forEach(Cache::invalidateAll);
            if (defaultLocalCache != null) {
                defaultLocalCache.invalidateAll();
            }
        }


        if (properties.getType() != ContexaCacheProperties.CacheType.LOCAL) {
            Set<String> keys = scanKeys(properties.getRedis().getKeyPrefix() + "*");
            if (!keys.isEmpty()) {
                redisTemplate.delete(keys);
            }
        }


        if (properties.getType() == ContexaCacheProperties.CacheType.HYBRID
                && properties.getPubsub().isEnabled()) {
            publishInvalidationEvent("*");
        }
    }


    @Override
    public void invalidateLocalOnly(String key) {
        if (properties.getType() == ContexaCacheProperties.CacheType.REDIS) {
            return;
        }


        if ("*".equals(key)) {
            domainCaches.values().forEach(Cache::invalidateAll);
            if (defaultLocalCache != null) {
                defaultLocalCache.invalidateAll();
            }
        } else if (key.contains("*")) {
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
    public ContexaCacheProperties.CacheType getCacheType() {
        return properties.getType();
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


    private void backfillToL1(String key, String json, String domain) {
        try {
            Cache<String, String> localCache = getOrCreateDomainCache(domain);
            localCache.put(key, json);
        } catch (Exception e) {
            log.error("L1 backfill failed: {}", key, e);
        }
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


    private int getRedisTtl(String domain) {
        if (domain == null) {
            return properties.getRedis().getDefaultTtlSeconds();
        }

        ContexaCacheProperties.DomainConfig domains = properties.getDomains();
        return switch (domain.toLowerCase()) {
            case "users" -> domains.getUsers().getRedisTtlSeconds();
            case "roles" -> domains.getRoles().getRedisTtlSeconds();
            case "permissions" -> domains.getPermissions().getRedisTtlSeconds();
            case "groups" -> domains.getGroups().getRedisTtlSeconds();
            case "policies" -> domains.getPolicies().getRedisTtlSeconds();
            case "soar" -> domains.getSoar().getRedisTtlSeconds();
            case "hcad" -> domains.getHcad().getRedisTtlSeconds();
            default -> properties.getRedis().getDefaultTtlSeconds();
        };
    }


    private Set<String> scanKeys(String pattern) {
        Set<String> keys = new java.util.HashSet<>();
        try (var cursor = redisTemplate.scan(
                ScanOptions.scanOptions().match(pattern).count(100).build())) {
            while (cursor.hasNext()) {
                keys.add(cursor.next());
            }
        }
        return keys;
    }

    private void publishInvalidationEvent(String key) {
        try {
            redisTemplate.convertAndSend(
                    properties.getPubsub().getChannel(),
                    key
            );
        } catch (Exception e) {
            log.error("Pub/Sub invalidation event publish failed: {}", key, e);
        }
    }
}
