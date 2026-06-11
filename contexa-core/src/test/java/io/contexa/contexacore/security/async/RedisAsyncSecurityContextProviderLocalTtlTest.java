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
package io.contexa.contexacore.security.async;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.RedisTemplate;

import java.lang.reflect.Field;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class RedisAsyncSecurityContextProviderLocalTtlTest {

    @Test
    @DisplayName("Custom local cache TTL is accepted through constructor injection")
    void customLocalCacheTtl_injectedThroughConstructor() throws Exception {
        @SuppressWarnings("unchecked")
        RedisTemplate<String, Object> redisTemplate = mock(RedisTemplate.class);
        Duration injected = Duration.ofMinutes(30);

        RedisAsyncSecurityContextProvider provider =
                new RedisAsyncSecurityContextProvider(redisTemplate, injected);

        Field field = RedisAsyncSecurityContextProvider.class.getDeclaredField("localCacheTtl");
        field.setAccessible(true);
        assertThat((Duration) field.get(provider)).isEqualTo(injected);
    }

    @Test
    @DisplayName("Default constructor retains the prior 5-minute local cache TTL for backward compatibility")
    void defaultLocalCacheTtl_backwardCompatible() throws Exception {
        @SuppressWarnings("unchecked")
        RedisTemplate<String, Object> redisTemplate = mock(RedisTemplate.class);

        RedisAsyncSecurityContextProvider provider =
                new RedisAsyncSecurityContextProvider(redisTemplate);

        Field field = RedisAsyncSecurityContextProvider.class.getDeclaredField("localCacheTtl");
        field.setAccessible(true);
        assertThat((Duration) field.get(provider)).isEqualTo(Duration.ofMinutes(5));
    }
}
