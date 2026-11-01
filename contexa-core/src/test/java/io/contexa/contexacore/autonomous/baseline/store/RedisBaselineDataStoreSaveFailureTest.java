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

import io.contexa.contexacommon.security.baseline.BaselineVector;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A Redis save that fails is reported to the learning that asked for it, not swallowed (QF-12). */
class RedisBaselineDataStoreSaveFailureTest {

    @Test
    @SuppressWarnings("unchecked")
    void aFailedSaveIsReportedAsNotStored() {
        RedisTemplate<String, Object> template = mock(RedisTemplate.class);
        when(template.execute(any(SessionCallback.class))).thenThrow(new RedisConnectionFailureException("Redis is down"));
        RedisBaselineDataStore store = new RedisBaselineDataStore(template);
        BaselineVector baseline = BaselineVector.builder().userId("user-1").build();

        assertThat(store.saveUserBaselineChecked("user-1", baseline)).isFalse();
    }
}
