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
package io.contexa.contexacore.autonomous.repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.util.DigestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
public class RedisProtectableRapidReentryRepository implements ProtectableRapidReentryRepository {

    private static final String KEY_PREFIX = "security:protectable:rapid-reentry:";
    private static final String KEY_PART_SEPARATOR = Character.toString(0);

    private final StringRedisTemplate stringRedisTemplate;

    @Override
    public boolean tryAcquire(String userId, String contextBindingHash, String resourceKey, Duration window) {
        if (isInvalid(userId) || isInvalid(contextBindingHash) || isInvalid(resourceKey) || window == null) {
            return true;
        }

        String key = buildKey(userId, contextBindingHash, resourceKey);
        try {
            Boolean acquired = stringRedisTemplate.opsForValue().setIfAbsent(key, "1", window);
            return Boolean.TRUE.equals(acquired);
        } catch (Exception e) {
            log.error("[ProtectableRapidReentry] Failed to acquire rapid reentry guard: userId={}", userId, e);
            return true;
        }
    }

    private String buildKey(String userId, String contextBindingHash, String resourceKey) {
        String raw = userId + KEY_PART_SEPARATOR + contextBindingHash + KEY_PART_SEPARATOR + resourceKey;
        String digest = DigestUtils.md5DigestAsHex(raw.getBytes(StandardCharsets.UTF_8));
        return KEY_PREFIX + digest;
    }

    private boolean isInvalid(String value) {
        return value == null || value.isBlank();
    }
}
