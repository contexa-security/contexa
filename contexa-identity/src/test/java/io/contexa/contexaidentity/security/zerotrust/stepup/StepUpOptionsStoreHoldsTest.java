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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Q-13: both stores tell whether a proof stands without spending it. */
class StepUpOptionsStoreHoldsTest {

    @Test
    @DisplayName("in memory an entry is held until it is taken, and looking does not take it")
    void inMemory() {
        InMemoryStepUpOptionsStore store = new InMemoryStepUpOptionsStore();

        store.put("held", Boolean.TRUE);

        assertThat(store.holds("held")).isTrue();
        assertThat(store.holds("held")).isTrue();
        store.take("held", Boolean.class);
        assertThat(store.holds("held")).isFalse();
    }

    @Test
    @DisplayName("in Redis the entry's key answers")
    void inRedis() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        when(redis.hasKey("contexa:step-up:options:held")).thenReturn(true);

        RedisStepUpOptionsStore store = new RedisStepUpOptionsStore(redis);

        assertThat(store.holds("held")).isTrue();
        assertThat(store.holds("other")).isFalse();
    }
}
