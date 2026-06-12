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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

@Slf4j
public class RedisAsyncSecurityContextProvider extends AbstractAsyncSecurityContextProvider {

    private static final String AUTH_KEY_PREFIX = "async:auth:";
    private static final String SESSION_KEY_PREFIX = "async:auth:session:";
    private static final Duration DEFAULT_LOCAL_CACHE_TTL = Duration.ofMinutes(5);

    private final RedisTemplate<String, Object> redisTemplate;
    private final Duration localCacheTtl;
    private final Cache<String, Optional<AsyncAuthenticationData>> authCache;

    public RedisAsyncSecurityContextProvider(RedisTemplate<String, Object> redisTemplate) {
        this(redisTemplate, DEFAULT_LOCAL_CACHE_TTL);
    }

    public RedisAsyncSecurityContextProvider(RedisTemplate<String, Object> redisTemplate,
                                             Duration localCacheTtl) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
        this.localCacheTtl = Objects.requireNonNull(localCacheTtl, "localCacheTtl");
        this.authCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(this.localCacheTtl)
                .build();
    }

    @Override
    protected void doSave(String userId, String sessionId, AsyncAuthenticationData data) {
        String userKey = AUTH_KEY_PREFIX + userId;
        redisTemplate.opsForValue().set(userKey, data, DEFAULT_TTL);
        authCache.put(userId, Optional.of(data));

        if (sessionId != null) {
            String compositeKey = AUTH_KEY_PREFIX + userId + ":" + sessionId;
            redisTemplate.opsForValue().set(compositeKey, data, DEFAULT_TTL);
            String sessionKey = SESSION_KEY_PREFIX + sessionId;
            redisTemplate.opsForValue().set(sessionKey, userId, DEFAULT_TTL);
        }
    }

    @Override
    protected Optional<AsyncAuthenticationData> resolveByUserId(String userId) {
        return authCache.get(userId, this::getAuthenticationByUserId);
    }

    @Override
    public Optional<AsyncAuthenticationData> getAuthenticationByUserId(String userId) {
        if (userId == null || userId.isEmpty()) {
            return Optional.empty();
        }

        try {
            String key = AUTH_KEY_PREFIX + userId;
            Object data = redisTemplate.opsForValue().get(key);

            if (data instanceof AsyncAuthenticationData authData) {
                if (authData.isValid()) {
                    return Optional.of(authData);
                }
            }
        } catch (Exception e) {
            log.error("Failed to get authentication by userId: {}", userId, e);
        }

        return Optional.empty();
    }

    @Override
    public Optional<AsyncAuthenticationData> getAuthenticationBySessionId(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            return Optional.empty();
        }

        try {
            String sessionKey = SESSION_KEY_PREFIX + sessionId;
            Object userIdObj = redisTemplate.opsForValue().get(sessionKey);

            if (userIdObj instanceof String userId) {
                String compositeKey = AUTH_KEY_PREFIX + userId + ":" + sessionId;
                Object data = redisTemplate.opsForValue().get(compositeKey);
                if (data instanceof AsyncAuthenticationData authData && authData.isValid()) {
                    return Optional.of(authData);
                }
                return getAuthenticationByUserId(userId);
            }
        } catch (Exception e) {
            log.error("Failed to get authentication by sessionId: {}", sessionId, e);
        }

        return Optional.empty();
    }

    @Override
    public void removeAuthentication(String userId, String sessionId) {
        try {
            if (userId != null) {
                redisTemplate.delete(AUTH_KEY_PREFIX + userId);
                authCache.invalidate(userId);
            }
            if (userId != null && sessionId != null) {
                redisTemplate.delete(AUTH_KEY_PREFIX + userId + ":" + sessionId);
            }
            if (sessionId != null) {
                redisTemplate.delete(SESSION_KEY_PREFIX + sessionId);
            }
        } catch (Exception e) {
            log.error("Failed to remove authentication - userId: {}, sessionId: {}", userId, sessionId, e);
        }
    }

    @Override
    public void refreshExpiration(String userId, String sessionId) {
        if (userId == null) {
            return;
        }

        try {
            String userKey = AUTH_KEY_PREFIX + userId;
            Object data = redisTemplate.opsForValue().get(userKey);

            if (data instanceof AsyncAuthenticationData authData) {
                authData.setExpiresAt(Instant.now().plus(DEFAULT_TTL));
                redisTemplate.opsForValue().set(userKey, authData, DEFAULT_TTL);
                authCache.invalidate(userId);

                if (sessionId != null) {
                    String compositeKey = AUTH_KEY_PREFIX + userId + ":" + sessionId;
                    redisTemplate.expire(compositeKey, DEFAULT_TTL);
                    String sessionKey = SESSION_KEY_PREFIX + sessionId;
                    redisTemplate.expire(sessionKey, DEFAULT_TTL);
                }
            }
        } catch (Exception e) {
            log.error("Failed to refresh expiration for userId: {}", userId, e);
        }
    }
}
