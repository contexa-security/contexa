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
package io.contexa.contexacore.autonomous.baseline.store;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A Redis read that fails is told apart from a missing baseline (W5-8). */
class RedisBaselineDataStoreReadFailureTest {

    @Test
    @SuppressWarnings("unchecked")
    void aFailedReadIsNotAMissingBaseline() {
        RedisTemplate<String, Object> template = mock(RedisTemplate.class);
        when(template.opsForHash()).thenThrow(new RedisConnectionFailureException("Redis is down"));
        RedisBaselineDataStore store = new RedisBaselineDataStore(template);

        assertThat(store.readUserBaseline("user-1").state()).isEqualTo(BaselineDataStore.BaselineRead.State.FAILED);
        assertThat(store.readOrganizationBaseline("org-1").state())
                .isEqualTo(BaselineDataStore.BaselineRead.State.FAILED);
        assertThat(store.getUserBaseline("user-1")).isNull();
    }
}
