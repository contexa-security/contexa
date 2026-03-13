package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AbstractContexaCacheServiceTest {

    @Mock
    private ContexaCacheProperties properties;

    private ObjectMapper objectMapper;
    private ConcreteContexaCacheService cacheService;

    /**
     * Concrete implementation of AbstractContexaCacheService for testing purposes.
     */
    private static class ConcreteContexaCacheService extends AbstractContexaCacheService {

        ConcreteContexaCacheService(ContexaCacheProperties properties, ObjectMapper objectMapper) {
            super(properties, objectMapper);
        }

        void initDefaultCache(int ttlSeconds) {
            defaultLocalCache = buildLocalCache(ttlSeconds);
        }

        // Expose protected methods for testing
        Cache<String, String> testGetOrCreateDomainCache(String domain) {
            return getOrCreateDomainCache(domain);
        }

        int testGetLocalTtl(String domain) {
            return getLocalTtl(domain);
        }

        Cache<String, String> testBuildLocalCache(int ttlSeconds) {
            return buildLocalCache(ttlSeconds);
        }

        @Override
        public <T> T get(String key, Supplier<T> loader, TypeReference<T> typeRef, String domain) {
            return null;
        }

        @Override
        public <T> void put(String key, T value, String domain) {
        }

        @Override
        public void invalidate(String key) {
        }

        @Override
        public void invalidateAll() {
        }

        @Override
        public void invalidateLocalOnly(String key) {
        }

        @Override
        public ContexaCacheProperties.CacheType getCacheType() {
            return ContexaCacheProperties.CacheType.LOCAL;
        }
    }

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();

        ContexaCacheProperties.LocalConfig localConfig = new ContexaCacheProperties.LocalConfig();
        localConfig.setMaxSize(100);
        localConfig.setDefaultTtlSeconds(60);
        when(properties.getLocal()).thenReturn(localConfig);

        cacheService = new ConcreteContexaCacheService(properties, objectMapper);
        cacheService.initDefaultCache(60);
    }

    @ParameterizedTest
    @CsvSource({
            "users, 3600",
            "roles, 14400",
            "permissions, 28800",
            "groups, 14400",
            "policies, 30",
            "soar, 900",
            "hcad, 86400"
    })
    @DisplayName("getLocalTtl should return domain-specific TTL")
    void getLocalTtl_shouldReturnDomainSpecificTtl(String domain, int expectedTtl) {
        // given
        ContexaCacheProperties.DomainConfig domainConfig = new ContexaCacheProperties.DomainConfig();
        when(properties.getDomains()).thenReturn(domainConfig);

        // when
        int ttl = cacheService.testGetLocalTtl(domain);

        // then
        assertThat(ttl).isEqualTo(expectedTtl);
    }

    @Test
    @DisplayName("getLocalTtl should return default TTL for unknown domain")
    void getLocalTtl_shouldReturnDefaultTtlForUnknownDomain() {
        // given
        ContexaCacheProperties.DomainConfig domainConfig = new ContexaCacheProperties.DomainConfig();
        when(properties.getDomains()).thenReturn(domainConfig);

        // when
        int ttl = cacheService.testGetLocalTtl("unknown-domain");

        // then
        assertThat(ttl).isEqualTo(60);
    }

    @Test
    @DisplayName("getLocalTtl should return default TTL for null domain")
    void getLocalTtl_shouldReturnDefaultTtlForNullDomain() {
        // when
        int ttl = cacheService.testGetLocalTtl(null);

        // then
        assertThat(ttl).isEqualTo(60);
    }

    @Test
    @DisplayName("getOrCreateDomainCache should return default cache for null domain")
    void getOrCreateDomainCache_shouldReturnDefaultCacheForNullDomain() {
        // when
        Cache<String, String> cache = cacheService.testGetOrCreateDomainCache(null);

        // then
        assertThat(cache).isNotNull();
        assertThat(cache).isSameAs(cacheService.testGetOrCreateDomainCache(null));
    }

    @Test
    @DisplayName("getOrCreateDomainCache should return default cache for empty domain")
    void getOrCreateDomainCache_shouldReturnDefaultCacheForEmptyDomain() {
        // when
        Cache<String, String> cache = cacheService.testGetOrCreateDomainCache("");

        // then
        assertThat(cache).isNotNull();
        assertThat(cache).isSameAs(cacheService.testGetOrCreateDomainCache(null));
    }

    @Test
    @DisplayName("getOrCreateDomainCache should create and reuse domain-specific cache")
    void getOrCreateDomainCache_shouldCreateAndReuseDomainCache() {
        // given
        ContexaCacheProperties.DomainConfig domainConfig = new ContexaCacheProperties.DomainConfig();
        when(properties.getDomains()).thenReturn(domainConfig);

        // when
        Cache<String, String> firstCall = cacheService.testGetOrCreateDomainCache("users");
        Cache<String, String> secondCall = cacheService.testGetOrCreateDomainCache("users");

        // then
        assertThat(firstCall).isNotNull();
        assertThat(firstCall).isSameAs(secondCall);
    }

    @Test
    @DisplayName("getOrCreateDomainCache should create different caches for different domains")
    void getOrCreateDomainCache_shouldCreateDifferentCachesForDifferentDomains() {
        // given
        ContexaCacheProperties.DomainConfig domainConfig = new ContexaCacheProperties.DomainConfig();
        when(properties.getDomains()).thenReturn(domainConfig);

        // when
        Cache<String, String> usersCache = cacheService.testGetOrCreateDomainCache("users");
        Cache<String, String> rolesCache = cacheService.testGetOrCreateDomainCache("roles");

        // then
        assertThat(usersCache).isNotSameAs(rolesCache);
    }

    @Test
    @DisplayName("buildLocalCache should create a functional cache")
    void buildLocalCache_shouldCreateFunctionalCache() {
        // when
        Cache<String, String> cache = cacheService.testBuildLocalCache(300);

        // then
        assertThat(cache).isNotNull();
        cache.put("key", "value");
        assertThat(cache.getIfPresent("key")).isEqualTo("value");
    }

    @Test
    @DisplayName("buildLocalCache should record stats")
    void buildLocalCache_shouldRecordStats() {
        // when
        Cache<String, String> cache = cacheService.testBuildLocalCache(300);

        // then
        cache.getIfPresent("nonexistent");
        assertThat(cache.stats().missCount()).isEqualTo(1);

        cache.put("key", "value");
        cache.getIfPresent("key");
        assertThat(cache.stats().hitCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("getLocalTtl should be case-insensitive for domain names")
    void getLocalTtl_shouldBeCaseInsensitive() {
        // given
        ContexaCacheProperties.DomainConfig domainConfig = new ContexaCacheProperties.DomainConfig();
        when(properties.getDomains()).thenReturn(domainConfig);

        // when
        int lowerTtl = cacheService.testGetLocalTtl("users");
        int upperTtl = cacheService.testGetLocalTtl("USERS");
        int mixedTtl = cacheService.testGetLocalTtl("Users");

        // then
        assertThat(lowerTtl).isEqualTo(upperTtl).isEqualTo(mixedTtl);
    }
}
