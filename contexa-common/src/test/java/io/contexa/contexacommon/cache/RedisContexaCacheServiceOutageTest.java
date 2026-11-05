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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * D-2 (PR-84): a cache that cannot be written is a cache without an entry, as the in-memory one never fails. The write that
 * follows a lookup used to reach the authorization check as an exception, which ended the request in a 500 and was
 * recorded as a refusal.
 */
class RedisContexaCacheServiceOutageTest {

    private static final TypeReference<String> TEXT = new TypeReference<>() {
    };

    @SuppressWarnings("unchecked")
    private static RedisContexaCacheService cacheOnRedisThatDoesNotAnswer() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(values.get(anyString())).thenThrow(new QueryTimeoutException("Redis command timed out"));
        doThrow(new QueryTimeoutException("Redis command timed out")).when(values)
                .set(anyString(), anyString(), anyLong(), eq(TimeUnit.SECONDS));
        return new RedisContexaCacheService(new ContexaCacheProperties(), redis, new ObjectMapper());
    }

    @Test
    @DisplayName("a lookup answers from its loader when Redis takes neither the read nor the write")
    void aLookupAnswersFromItsLoader() {
        assertThat(cacheOnRedisThatDoesNotAnswer().get("user_details:2", () -> "the user", TEXT, "users")).isEqualTo("the user");
    }

    @Test
    @DisplayName("a write Redis does not take does not reach the caller")
    void aWriteRedisDoesNotTakeDoesNotReachTheCaller() {
        assertThatCode(() -> cacheOnRedisThatDoesNotAnswer().put("user_details:2", "the user", "users")).doesNotThrowAnyException();
    }
}
