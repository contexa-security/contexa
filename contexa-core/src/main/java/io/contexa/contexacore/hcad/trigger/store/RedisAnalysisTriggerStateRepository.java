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
package io.contexa.contexacore.hcad.trigger.store;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

public class RedisAnalysisTriggerStateRepository implements AnalysisTriggerStateRepository {

    private final StringRedisTemplate stringRedisTemplate;

    public RedisAnalysisTriggerStateRepository(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
    }

    @Override
    public boolean isNegativeCached(String baseKey) {
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(ZeroTrustRedisKeys.analysisTriggerNegative(baseKey)));
    }

    @Override
    public void markNegative(String baseKey, Duration ttl) {
        if (baseKey == null || ttl == null || ttl.isZero() || ttl.isNegative()) {
            return;
        }
        stringRedisTemplate.opsForValue().set(ZeroTrustRedisKeys.analysisTriggerNegative(baseKey), "1", ttl);
    }

    @Override
    public boolean isCoolingDown(String dedupKey) {
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(ZeroTrustRedisKeys.analysisTriggerCooldown(dedupKey)));
    }

    @Override
    public boolean isInFlight(String dedupKey) {
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(ZeroTrustRedisKeys.analysisTriggerInflight(dedupKey)));
    }
    @Override
    public boolean tryAcquireInFlight(String dedupKey, Duration ttl) {
        if (dedupKey == null || ttl == null || ttl.isZero() || ttl.isNegative()) {
            return false;
        }
        Boolean acquired = stringRedisTemplate.opsForValue()
                .setIfAbsent(ZeroTrustRedisKeys.analysisTriggerInflight(dedupKey), "1", ttl);
        return Boolean.TRUE.equals(acquired);
    }

    @Override
    public void markCooldown(String dedupKey, Duration ttl) {
        if (dedupKey == null || ttl == null || ttl.isZero() || ttl.isNegative()) {
            return;
        }
        stringRedisTemplate.opsForValue().set(ZeroTrustRedisKeys.analysisTriggerCooldown(dedupKey), "1", ttl);
    }

    @Override
    public void releaseInFlight(String dedupKey) {
        if (dedupKey != null) {
            stringRedisTemplate.delete(ZeroTrustRedisKeys.analysisTriggerInflight(dedupKey));
        }
    }
}
