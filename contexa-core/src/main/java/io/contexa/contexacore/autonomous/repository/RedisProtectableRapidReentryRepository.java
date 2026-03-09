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
        String raw = userId + ":" + contextBindingHash + ":" + resourceKey;
        String digest = DigestUtils.md5DigestAsHex(raw.getBytes(StandardCharsets.UTF_8));
        return KEY_PREFIX + digest;
    }

    private boolean isInvalid(String value) {
        return value == null || value.isBlank();
    }
}
