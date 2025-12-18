package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Contexa 2-Level 캐시 서비스
 *
 * 분산 환경에서 일관성을 보장하는 캐시 서비스:
 * - L1: Caffeine (로컬 인메모리, 초저지연)
 * - L2: Redis (분산, 일관성)
 * - Pub/Sub: 분산 노드 간 캐시 무효화
 *
 * 사용 예시:
 * <pre>
 * // 캐시 조회 (L1 -> L2 -> DB 순서)
 * List<Policy> policies = cacheService.get("policies:method:MyService.myMethod",
 *     () -> policyRepository.findByMethodIdentifier("MyService.myMethod"),
 *     new TypeReference<List<Policy>>() {},
 *     "policies");
 *
 * // 캐시 무효화 (L1 + L2 + Pub/Sub)
 * cacheService.invalidate("policies:method:*");
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@RequiredArgsConstructor
public class ContexaCacheService {

    private final ContexaCacheProperties properties;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    /**
     * 도메인별 L1 캐시 맵
     * 도메인별로 다른 TTL을 적용하기 위해 별도 캐시 인스턴스 사용
     */
    private final ConcurrentHashMap<String, Cache<String, String>> domainCaches = new ConcurrentHashMap<>();

    /**
     * 기본 L1 캐시 (도메인 미지정 시 사용)
     */
    private Cache<String, String> defaultLocalCache;

    @PostConstruct
    public void init() {
        if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {
            // LOCAL 또는 HYBRID 모드일 때 L1 캐시 초기화
            defaultLocalCache = buildLocalCache(properties.getLocal().getDefaultTtlSeconds());
            log.info("ContexaCacheService 초기화 완료 - type: {}, L1 maxSize: {}, L1 TTL: {}s",
                properties.getType(),
                properties.getLocal().getMaxSize(),
                properties.getLocal().getDefaultTtlSeconds());
        } else {
            log.info("ContexaCacheService 초기화 완료 - type: REDIS (L1 캐시 비활성화)");
        }
    }

    /**
     * 캐시에서 값 조회 (L1 -> L2 -> loader 순서)
     *
     * @param key 캐시 키
     * @param loader 캐시 미스 시 데이터 로드 함수
     * @param typeRef 반환 타입 참조
     * @param domain 도메인 (TTL 결정용, null이면 기본값)
     * @param <T> 반환 타입
     * @return 캐시된 값 또는 로드된 값
     */
    public <T> T get(String key, Supplier<T> loader, TypeReference<T> typeRef, String domain) {
        // 1. L1 캐시 조회 (LOCAL 또는 HYBRID)
        if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {
            Cache<String, String> localCache = getOrCreateDomainCache(domain);
            String cachedJson = localCache.getIfPresent(key);
            if (cachedJson != null) {
                try {
                    log.trace("L1 캐시 히트: {}", key);
                    return objectMapper.readValue(cachedJson, typeRef);
                } catch (JsonProcessingException e) {
                    log.warn("L1 캐시 역직렬화 실패: {}", key, e);
                    localCache.invalidate(key);
                }
            }
        }

        // 2. L2 캐시 조회 (REDIS 또는 HYBRID)
        if (properties.getType() != ContexaCacheProperties.CacheType.LOCAL) {
            String redisKey = properties.getRedis().getKeyPrefix() + key;
            try {
                String redisJson = redisTemplate.opsForValue().get(redisKey);
                if (redisJson != null) {
                    T value = objectMapper.readValue(redisJson, typeRef);
                    // L1 백필 (HYBRID)
                    if (properties.getType() == ContexaCacheProperties.CacheType.HYBRID) {
                        backfillToL1(key, redisJson, domain);
                    }
                    log.trace("L2 캐시 히트 (Redis): {}", key);
                    return value;
                }
            } catch (Exception e) {
                log.warn("L2 캐시 조회 실패: {}", key, e);
            }
        }

        // 3. 캐시 미스 - 데이터 로드 및 캐시 저장
        log.trace("캐시 미스, 데이터 로드: {}", key);
        T value = loader.get();
        if (value != null) {
            put(key, value, domain);
        }
        return value;
    }

    /**
     * 캐시에 값 저장 (L1 + L2)
     *
     * @param key 캐시 키
     * @param value 저장할 값
     * @param domain 도메인 (TTL 결정용)
     * @param <T> 값 타입
     */
    public <T> void put(String key, T value, String domain) {
        try {
            String json = objectMapper.writeValueAsString(value);

            // L1 저장
            if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {
                Cache<String, String> localCache = getOrCreateDomainCache(domain);
                localCache.put(key, json);
            }

            // L2 저장
            if (properties.getType() != ContexaCacheProperties.CacheType.LOCAL) {
                String redisKey = properties.getRedis().getKeyPrefix() + key;
                int ttlSeconds = getRedisTtl(domain);
                redisTemplate.opsForValue().set(redisKey, json, ttlSeconds, TimeUnit.SECONDS);
            }

            log.trace("캐시 저장 완료: {}", key);

        } catch (JsonProcessingException e) {
            log.error("캐시 직렬화 실패: {}", key, e);
        }
    }

    /**
     * 특정 키 무효화 (L1 + L2 + Pub/Sub)
     *
     * @param key 무효화할 키 (와일드카드 지원: "policies:*")
     */
    public void invalidate(String key) {
        log.debug("캐시 무효화 요청: {}", key);

        // L1 무효화
        if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {
            if (key.contains("*")) {
                // 와일드카드 - 모든 도메인 캐시에서 패턴 매칭 무효화
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
                // 정확한 키
                domainCaches.values().forEach(cache -> cache.invalidate(key));
                if (defaultLocalCache != null) {
                    defaultLocalCache.invalidate(key);
                }
            }
        }

        // L2 무효화
        if (properties.getType() != ContexaCacheProperties.CacheType.LOCAL) {
            String redisPattern = properties.getRedis().getKeyPrefix() + key;
            if (key.contains("*")) {
                Set<String> keys = redisTemplate.keys(redisPattern);
                if (keys != null && !keys.isEmpty()) {
                    redisTemplate.delete(keys);
                    log.debug("L2 캐시 무효화 완료: {} 키", keys.size());
                }
            } else {
                redisTemplate.delete(redisPattern);
            }
        }

        // Pub/Sub 분산 무효화 (HYBRID)
        if (properties.getType() == ContexaCacheProperties.CacheType.HYBRID
            && properties.getPubsub().isEnabled()) {
            publishInvalidationEvent(key);
        }
    }

    /**
     * 모든 캐시 무효화 (L1 + L2 + Pub/Sub)
     */
    public void invalidateAll() {
        log.info("전체 캐시 무효화 요청");

        // L1 무효화
        if (properties.getType() != ContexaCacheProperties.CacheType.REDIS) {
            domainCaches.values().forEach(Cache::invalidateAll);
            if (defaultLocalCache != null) {
                defaultLocalCache.invalidateAll();
            }
        }

        // L2 무효화
        if (properties.getType() != ContexaCacheProperties.CacheType.LOCAL) {
            Set<String> keys = redisTemplate.keys(properties.getRedis().getKeyPrefix() + "*");
            if (keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
                log.info("L2 캐시 무효화 완료: {} 키", keys.size());
            }
        }

        // Pub/Sub 분산 무효화 (HYBRID)
        if (properties.getType() == ContexaCacheProperties.CacheType.HYBRID
            && properties.getPubsub().isEnabled()) {
            publishInvalidationEvent("*");
        }
    }

    /**
     * L1 캐시만 무효화 (Pub/Sub 수신 시 사용)
     *
     * @param key 무효화할 키
     */
    public void invalidateLocalOnly(String key) {
        if (properties.getType() == ContexaCacheProperties.CacheType.REDIS) {
            return;
        }

        log.debug("L1 캐시만 무효화: {}", key);

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

    /**
     * 도메인별 L1 캐시 조회 또는 생성
     */
    private Cache<String, String> getOrCreateDomainCache(String domain) {
        if (domain == null || domain.isEmpty()) {
            return defaultLocalCache;
        }

        return domainCaches.computeIfAbsent(domain, d -> {
            int ttl = getLocalTtl(d);
            return buildLocalCache(ttl);
        });
    }

    /**
     * L1 캐시 인스턴스 생성
     */
    private Cache<String, String> buildLocalCache(int ttlSeconds) {
        return Caffeine.newBuilder()
            .maximumSize(properties.getLocal().getMaxSize())
            .expireAfterWrite(ttlSeconds, TimeUnit.SECONDS)
            .recordStats()
            .build();
    }

    /**
     * L1 백필 (L2에서 조회 후 L1에 저장)
     */
    private void backfillToL1(String key, String json, String domain) {
        try {
            Cache<String, String> localCache = getOrCreateDomainCache(domain);
            localCache.put(key, json);
            log.trace("L1 백필 완료: {}", key);
        } catch (Exception e) {
            log.warn("L1 백필 실패: {}", key, e);
        }
    }

    /**
     * 도메인별 L1 TTL 조회
     */
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

    /**
     * 도메인별 L2 TTL 조회
     */
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

    /**
     * Pub/Sub 무효화 이벤트 발행
     */
    private void publishInvalidationEvent(String key) {
        try {
            redisTemplate.convertAndSend(
                properties.getPubsub().getChannel(),
                key
            );
            log.debug("Pub/Sub 무효화 이벤트 발행: {}", key);
        } catch (Exception e) {
            log.error("Pub/Sub 무효화 이벤트 발행 실패: {}", key, e);
        }
    }

    /**
     * 캐시 타입 조회
     */
    public ContexaCacheProperties.CacheType getCacheType() {
        return properties.getType();
    }
}
