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
package io.contexa.contexaidentity.security.zerotrust.stepup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * D-19: the in-memory store of the step-up never fails, so a step-up screen does not expect it to. While Redis is away a
 * step-up cannot be finished, and the screen says so instead of ending in a server error; the user stays stopped.
 */
class RedisStepUpOptionsStoreOutageTest {

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final RedisStepUpOptionsStore store = new RedisStepUpOptionsStore(redis);

    @BeforeEach
    @SuppressWarnings("unchecked")
    void redisStopsAnswering() {
        ValueOperations<String, String> values = mock(ValueOperations.class);
        QueryTimeoutException noAnswer = new QueryTimeoutException("Redis command timed out");
        when(redis.opsForValue()).thenReturn(values);
        when(values.setIfAbsent(anyString(), anyString(), any(Duration.class))).thenThrow(noAnswer);
        when(values.getAndDelete(anyString())).thenThrow(noAnswer);
        doThrow(noAnswer).when(values).set(anyString(), anyString(), any(Duration.class));
        when(redis.delete(anyString())).thenThrow(noAnswer);
    }

    @Test
    @DisplayName("a claim Redis cannot give is not given, so a code is not spent and nothing is sent twice")
    void aClaimIsNotGiven() {
        assertThat(store.claim("code-spent", Duration.ofMinutes(1))).isFalse();
    }

    @Test
    @DisplayName("an option that cannot be read is an option the answer does not find")
    void anOptionThatCannotBeReadIsAbsent() {
        assertThat(store.take("assertion", String.class)).isNull();
    }

    @Test
    @DisplayName("an option Redis does not take does not fail the screen that hands it out")
    void anOptionRedisDoesNotTake() {
        assertThatCode(() -> store.put("assertion", "options")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a count Redis cannot keep reads as past every limit, so no code is looked at")
    @SuppressWarnings("unchecked")
    void aCountThatCannotBeKeptIsPastTheLimit() {
        when(redis.execute(any(RedisScript.class), anyList(), any(Object[].class)))
                .thenThrow(new QueryTimeoutException("Redis command timed out"));

        assertThat(store.increment("code-attempts", Duration.ofMinutes(5))).isEqualTo(Long.MAX_VALUE);
    }

    @Test
    @DisplayName("a count Redis cannot clear lapses with its time")
    void aClearRedisDoesNotTake() {
        assertThatCode(() -> store.clearCount("code-attempts")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a release Redis does not take lapses with its time")
    void aReleaseRedisDoesNotTake() {
        assertThatCode(() -> store.release("code-sent")).doesNotThrowAnyException();
    }
}
