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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Z-16 (4.3, F2): with the default settings a cached entry lasts as long in either mode, the shorter of the two
 * former defaults, so that a change made outside the application reaches both modes within the same time.
 */
class ContexaCacheTtlParityTest {

    @ParameterizedTest
    @ValueSource(strings = {"users", "roles", "permissions", "groups", "policies", "soar", "anything-else"})
    void aDomainKeepsItsEntriesAsLongInEitherMode(String domain) {
        assertThat(redisTtlSeconds(domain)).as(domain).isEqualTo(localTtlSeconds(domain));
    }

    @Test
    void entriesWithoutADomainLastAsLongInEitherMode() {
        assertThat(redisTtlSeconds(null)).isEqualTo(localTtlSeconds(null));
    }

    @Test
    void policiesAndTheDefaultTakeTheShorterFormerDefault() {
        assertThat(localTtlSeconds("policies")).isEqualTo(30);
        assertThat(redisTtlSeconds("policies")).isEqualTo(30);
        assertThat(localTtlSeconds(null)).isEqualTo(60);
        assertThat(redisTtlSeconds(null)).isEqualTo(60);
    }

    private static long localTtlSeconds(String domain) {
        return new LocalContexaCacheService(new ContexaCacheProperties(), new ObjectMapper()).getLocalTtl(domain);
    }

    /** The TTL the Redis cache writes an entry of the domain with. */
    @SuppressWarnings("unchecked")
    private static long redisTtlSeconds(String domain) {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        RedisContexaCacheService cache = new RedisContexaCacheService(new ContexaCacheProperties(), redis,
                new ObjectMapper());
        cache.put("entry", "value", domain);
        ArgumentCaptor<Long> ttl = ArgumentCaptor.forClass(Long.class);
        verify(values).set(eq("contexa:cache:entry"), anyString(), ttl.capture(), eq(TimeUnit.SECONDS));
        return ttl.getValue();
    }
}
