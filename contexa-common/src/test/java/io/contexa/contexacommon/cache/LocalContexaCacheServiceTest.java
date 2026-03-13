package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LocalContexaCacheServiceTest {

    @Mock
    private ContexaCacheProperties properties;

    private ObjectMapper objectMapper;
    private LocalContexaCacheService cacheService;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();

        ContexaCacheProperties.LocalConfig localConfig = new ContexaCacheProperties.LocalConfig();
        localConfig.setMaxSize(100);
        localConfig.setDefaultTtlSeconds(60);
        when(properties.getLocal()).thenReturn(localConfig);

        ContexaCacheProperties.DomainConfig domainConfig = new ContexaCacheProperties.DomainConfig();
        when(properties.getDomains()).thenReturn(domainConfig);

        cacheService = new LocalContexaCacheService(properties, objectMapper);
        cacheService.init();
    }

    @Test
    @DisplayName("put then get should return cached value (cache hit)")
    void putThenGet_shouldReturnCachedValue() {
        // given
        String key = "test-key";
        String value = "test-value";
        TypeReference<String> typeRef = new TypeReference<>() {};

        // when
        cacheService.put(key, value, null);
        String result = cacheService.get(key, () -> "loader-value", typeRef, null);

        // then
        assertThat(result).isEqualTo("test-value");
    }

    @Test
    @DisplayName("get should invoke loader on cache miss")
    void get_shouldInvokeLoaderOnCacheMiss() {
        // given
        String key = "missing-key";
        TypeReference<String> typeRef = new TypeReference<>() {};

        // when
        String result = cacheService.get(key, () -> "loaded-value", typeRef, null);

        // then
        assertThat(result).isEqualTo("loaded-value");
    }

    @Test
    @DisplayName("get should cache value from loader for subsequent calls")
    void get_shouldCacheLoaderValueForSubsequentCalls() {
        // given
        String key = "new-key";
        TypeReference<String> typeRef = new TypeReference<>() {};
        int[] loaderCallCount = {0};

        // when - first call triggers loader
        cacheService.get(key, () -> {
            loaderCallCount[0]++;
            return "loaded-value";
        }, typeRef, null);

        // second call should hit cache
        String result = cacheService.get(key, () -> {
            loaderCallCount[0]++;
            return "should-not-be-returned";
        }, typeRef, null);

        // then
        assertThat(loaderCallCount[0]).isEqualTo(1);
        assertThat(result).isEqualTo("loaded-value");
    }

    @Test
    @DisplayName("invalidate should remove exact key from cache")
    void invalidate_shouldRemoveExactKey() {
        // given
        String key = "to-remove";
        TypeReference<String> typeRef = new TypeReference<>() {};
        cacheService.put(key, "value", null);

        // when
        cacheService.invalidate(key);
        String result = cacheService.get(key, () -> "reloaded", typeRef, null);

        // then
        assertThat(result).isEqualTo("reloaded");
    }

    @Test
    @DisplayName("invalidate with wildcard should remove matching keys")
    void invalidate_withWildcard_shouldRemoveMatchingKeys() {
        // given
        TypeReference<String> typeRef = new TypeReference<>() {};
        cacheService.put("user:1", "user1", null);
        cacheService.put("user:2", "user2", null);
        cacheService.put("role:1", "role1", null);

        // when
        cacheService.invalidate("user:*");

        // then
        String user1Result = cacheService.get("user:1", () -> "reloaded-user1", typeRef, null);
        String user2Result = cacheService.get("user:2", () -> "reloaded-user2", typeRef, null);
        String role1Result = cacheService.get("role:1", () -> "reloaded-role1", typeRef, null);

        assertThat(user1Result).isEqualTo("reloaded-user1");
        assertThat(user2Result).isEqualTo("reloaded-user2");
        assertThat(role1Result).isEqualTo("role1");
    }

    @Test
    @DisplayName("invalidateAll should clear all cached entries")
    void invalidateAll_shouldClearAllEntries() {
        // given
        TypeReference<String> typeRef = new TypeReference<>() {};
        cacheService.put("key1", "value1", null);
        cacheService.put("key2", "value2", null);

        // when
        cacheService.invalidateAll();

        // then
        String result1 = cacheService.get("key1", () -> "reloaded1", typeRef, null);
        String result2 = cacheService.get("key2", () -> "reloaded2", typeRef, null);

        assertThat(result1).isEqualTo("reloaded1");
        assertThat(result2).isEqualTo("reloaded2");
    }

    @Test
    @DisplayName("getCacheType should return LOCAL")
    void getCacheType_shouldReturnLocal() {
        assertThat(cacheService.getCacheType()).isEqualTo(ContexaCacheProperties.CacheType.LOCAL);
    }

    @Test
    @DisplayName("put and get with domain should use domain-specific cache")
    void putAndGet_withDomain_shouldUseDomainSpecificCache() {
        // given
        String key = "domain-key";
        String domain = "users";
        TypeReference<String> typeRef = new TypeReference<>() {};

        // when
        cacheService.put(key, "domain-value", domain);
        String result = cacheService.get(key, () -> "loader-value", typeRef, domain);

        // then
        assertThat(result).isEqualTo("domain-value");
    }

    @Test
    @DisplayName("Different domains should have independent caches")
    void differentDomains_shouldHaveIndependentCaches() {
        // given
        String key = "shared-key";
        TypeReference<String> typeRef = new TypeReference<>() {};

        // when
        cacheService.put(key, "users-value", "users");
        cacheService.put(key, "roles-value", "roles");

        // then
        String usersResult = cacheService.get(key, () -> "fallback", typeRef, "users");
        String rolesResult = cacheService.get(key, () -> "fallback", typeRef, "roles");

        assertThat(usersResult).isEqualTo("users-value");
        assertThat(rolesResult).isEqualTo("roles-value");
    }
}
