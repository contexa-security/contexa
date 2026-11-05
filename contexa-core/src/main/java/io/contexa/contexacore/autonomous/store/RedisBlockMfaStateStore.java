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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Slf4j
public class RedisBlockMfaStateStore implements BlockMfaStateStore {

    private final StringRedisTemplate stringRedisTemplate;
    private final ZeroTrustActionRepository actionRepository;
    private final Duration verifiedTtl;

    private static final Duration DEFAULT_VERIFIED_TTL = Duration.ofHours(1);

    /** Between the time of a verification and the context it was passed in, in the one key the release removes. */
    private static final char CONTEXT_SEPARATOR = '|';

    public RedisBlockMfaStateStore(StringRedisTemplate stringRedisTemplate,
                                   ZeroTrustActionRepository actionRepository) {
        this(stringRedisTemplate, actionRepository, DEFAULT_VERIFIED_TTL);
    }

    public RedisBlockMfaStateStore(StringRedisTemplate stringRedisTemplate,
                                   ZeroTrustActionRepository actionRepository,
                                   Duration verifiedTtl) {
        this.stringRedisTemplate = Objects.requireNonNull(stringRedisTemplate, "stringRedisTemplate");
        this.actionRepository = Objects.requireNonNull(actionRepository, "actionRepository");
        this.verifiedTtl = Objects.requireNonNull(verifiedTtl, "verifiedTtl");
    }

    @Override
    public void setVerified(String userId) {
        setVerified(userId, null);
    }

    @Override
    public void setVerified(String userId, @Nullable String contextBindingHash) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaVerified(userId);
            String value = Instant.now() + (contextBindingHash != null ? CONTEXT_SEPARATOR + contextBindingHash : "");
            stringRedisTemplate.opsForValue().set(key, value, verifiedTtl);
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to set verified: userId={}", userId, e);
        }
    }

    @Override
    public boolean isVerified(String userId, @Nullable String contextBindingHash) {
        if (contextBindingHash == null || contextBindingHash.isEmpty()) {
            return false;
        }
        try {
            String value = stringRedisTemplate.opsForValue().get(ZeroTrustRedisKeys.blockMfaVerified(userId));
            int separator = value != null ? value.indexOf(CONTEXT_SEPARATOR) : -1;
            return separator >= 0 && contextBindingHash.equals(value.substring(separator + 1));
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to check verified: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public boolean isVerified(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaVerified(userId);
            String value = stringRedisTemplate.opsForValue().get(key);
            return value != null && !value.isBlank() && !"false".equalsIgnoreCase(value);
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to check verified: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public Instant getVerifiedAt(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaVerified(userId);
            String value = stringRedisTemplate.opsForValue().get(key);
            if (value == null || value.isBlank() || "true".equalsIgnoreCase(value)) {
                return null;
            }
            int separator = value.indexOf(CONTEXT_SEPARATOR);
            return Instant.parse(separator >= 0 ? value.substring(0, separator) : value);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Instant getVerifiedExpiresAt(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaVerified(userId);
            Long ttlMs = stringRedisTemplate.getExpire(key, TimeUnit.MILLISECONDS);
            if (ttlMs == null || ttlMs <= 0) {
                return null;
            }
            return Instant.now().plusMillis(ttlMs);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void setPending(String userId) {
        actionRepository.setBlockMfaPending(userId);
    }

    @Override
    public void clearPending(String userId) {
        actionRepository.clearBlockMfaPending(userId);
    }

    @Override
    public int getFailCount(String userId) {
        return (int) actionRepository.getBlockMfaFailCount(userId);
    }

    @Override
    public void clearUser(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        stringRedisTemplate.delete(ZeroTrustRedisKeys.blockMfaVerified(userId));
        actionRepository.clearBlockMfaPending(userId);
    }
}
