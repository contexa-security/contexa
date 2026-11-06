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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.store.ApplicationNamespace;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What the cache keeps in Redis, the pattern it removes by and the channel it announces on are a named application's own,
 * so that two applications sharing a Redis share no entry and no invalidation.
 */
class RedisContexaCacheServiceApplicationTest {

    private static final TypeReference<String> TEXT = new TypeReference<>() {
    };

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private final ContexaCacheProperties properties = new ContexaCacheProperties();

    private RedisContexaCacheService cache() {
        when(redis.opsForValue()).thenReturn(values);
        properties.setType(ContexaCacheProperties.CacheType.HYBRID);
        RedisContexaCacheService cache = new RedisContexaCacheService(properties, redis, new ObjectMapper());
        cache.init();
        return cache;
    }

    @Test
    @DisplayName("an entry is written and read under ctxa:<name>: before the prefix of the cache")
    void entriesAreBehindTheName() {
        RedisContexaCacheService cache = cache();

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            cache.put("user_details:2", "the user", "users");
            assertThat(cache.get("user_details:3", () -> "loaded", TEXT, "other")).isEqualTo("loaded");
        }

        verify(values).set(eq("ctxa:shop:contexa:cache:user_details:2"), anyString(), anyLong(), eq(TimeUnit.SECONDS));
        verify(values).get("ctxa:shop:contexa:cache:user_details:3");
    }

    @Test
    @DisplayName("an application without a name keeps the key it always had")
    void anUnnamedApplicationKeepsItsKey() {
        RedisContexaCacheService cache = cache();

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            cache.put("user_details:2", "the user", "users");
        }

        verify(values).set(eq("contexa:cache:user_details:2"), anyString(), anyLong(), eq(TimeUnit.SECONDS));
    }

    @Test
    @DisplayName("removing by a pattern and removing all scan only the keys behind the name, and announce on the channel behind it")
    @SuppressWarnings("unchecked")
    void patternsAndChannelAreBehindTheName() {
        RedisContexaCacheService cache = cache();
        Cursor<String> none = mock(Cursor.class);
        when(none.hasNext()).thenReturn(false);
        when(redis.scan(any(ScanOptions.class))).thenReturn(none);
        when(redis.delete(ArgumentMatchers.<Set<String>>any())).thenReturn(0L);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            cache.invalidate("user_details:*");
            cache.invalidateAll();
        }

        ArgumentCaptor<ScanOptions> scans = ArgumentCaptor.forClass(ScanOptions.class);
        verify(redis, times(2)).scan(scans.capture());
        assertThat(scans.getAllValues()).extracting(ScanOptions::getPattern)
                .containsExactly("ctxa:shop:contexa:cache:user_details:*", "ctxa:shop:contexa:cache:*");
        verify(redis).convertAndSend("ctxa:shop:contexa:cache:invalidation", "user_details:*");
        verify(redis).convertAndSend("ctxa:shop:contexa:cache:invalidation", "*");
    }

    @Test
    @DisplayName("the listener takes only the invalidations announced on the channel of its own application")
    void theListenerHearsOnlyItsOwnChannel() {
        ContexaCacheService cache = mock(ContexaCacheService.class);
        ContexaCacheInvalidationListener listener = new ContexaCacheInvalidationListener(cache, properties);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            listener.handleMessage("user_details:2", "ctxa:clinic:contexa:cache:invalidation");
            listener.handleMessage("user_details:3", "contexa:cache:invalidation");
            listener.handleMessage("user_details:4", "ctxa:shop:contexa:cache:invalidation");
        }

        verify(cache).invalidateLocalOnly("user_details:4");
        verify(cache, never()).invalidateLocalOnly("user_details:2");
        verify(cache, never()).invalidateLocalOnly("user_details:3");
    }
}
