package io.contexa.contexacore.security.async;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
public class AsyncSecurityContextProvider {

    private static final String AUTH_KEY_PREFIX = "async:auth:";
    private static final String SESSION_KEY_PREFIX = "async:auth:session:";
    private static final Duration DEFAULT_TTL = Duration.ofHours(24);

    private final RedisTemplate<String, Object> redisTemplate;

    public AsyncSecurityContextProvider(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void saveAuthenticationForAsync(Authentication auth, String sessionId) {
        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        String userId = auth.getName();
        if (userId == null || "anonymousUser".equals(userId)) {
            return;
        }

        try {
            Instant now = Instant.now();
            AsyncAuthenticationData data = AsyncAuthenticationData.builder()
                    .userId(userId)
                    .sessionId(sessionId)
                    .principalType(auth.getPrincipal() != null
                            ? auth.getPrincipal().getClass().getSimpleName()
                            : "Unknown")
                    .authorities(auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList()))
                    .createdAt(now)
                    .expiresAt(now.plus(DEFAULT_TTL))
                    .build();

            String userKey = sessionId != null
                    ? AUTH_KEY_PREFIX + userId + ":" + sessionId
                    : AUTH_KEY_PREFIX + userId;
            redisTemplate.opsForValue().set(userKey, data, DEFAULT_TTL);

            if (sessionId != null) {
                String sessionKey = SESSION_KEY_PREFIX + sessionId;
                redisTemplate.opsForValue().set(sessionKey, userId, DEFAULT_TTL);
            }

        } catch (Exception e) {
            log.error("Failed to save authentication for async context - userId: {}", userId, e);
        }
    }

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

    public Optional<AsyncAuthenticationData> getCurrentAuthentication(String fallbackUserId) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                return getAuthenticationByUserId(auth.getName());
            }
        } catch (Exception ignored) {
        }

        if (fallbackUserId != null) {
            return getAuthenticationByUserId(fallbackUserId);
        }

        return Optional.empty();
    }

    public void removeAuthentication(String userId, String sessionId) {
        try {
            if (userId != null && sessionId != null) {
                redisTemplate.delete(AUTH_KEY_PREFIX + userId + ":" + sessionId);
            } else if (userId != null) {
                redisTemplate.delete(AUTH_KEY_PREFIX + userId);
            }
            if (sessionId != null) {
                redisTemplate.delete(SESSION_KEY_PREFIX + sessionId);
            }
        } catch (Exception e) {
            log.error("Failed to remove authentication - userId: {}, sessionId: {}", userId, sessionId, e);
        }
    }

    public void refreshExpiration(String userId, String sessionId) {
        if (userId == null) {
            return;
        }

        try {
            String userKey = sessionId != null
                    ? AUTH_KEY_PREFIX + userId + ":" + sessionId
                    : AUTH_KEY_PREFIX + userId;
            Object data = redisTemplate.opsForValue().get(userKey);

            if (data instanceof AsyncAuthenticationData authData) {
                authData.setExpiresAt(Instant.now().plus(DEFAULT_TTL));
                redisTemplate.opsForValue().set(userKey, authData, DEFAULT_TTL);

                if (sessionId != null) {
                    String sessionKey = SESSION_KEY_PREFIX + sessionId;
                    redisTemplate.expire(sessionKey, DEFAULT_TTL);
                }
            }
        } catch (Exception e) {
            log.error("Failed to refresh expiration for userId: {}", userId, e);
        }
    }
}
