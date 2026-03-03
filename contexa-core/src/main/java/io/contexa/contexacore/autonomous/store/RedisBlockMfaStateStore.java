package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
public class RedisBlockMfaStateStore implements BlockMfaStateStore {

    private final StringRedisTemplate stringRedisTemplate;

    private static final Duration VERIFIED_TTL = Duration.ofHours(1);
    private static final Duration PENDING_TTL = Duration.ofMinutes(10);

    @Override
    public void setVerified(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaVerified(userId);
            stringRedisTemplate.opsForValue().set(key, "true", VERIFIED_TTL);
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to set verified: userId={}", userId, e);
        }
    }

    @Override
    public boolean isVerified(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaVerified(userId);
            return Boolean.parseBoolean(stringRedisTemplate.opsForValue().get(key));
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to check verified: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public void setPending(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaPending(userId);
            stringRedisTemplate.opsForValue().set(key, "true", PENDING_TTL);
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to set pending: userId={}", userId, e);
        }
    }

    @Override
    public void clearPending(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaPending(userId);
            stringRedisTemplate.delete(key);
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to clear pending: userId={}", userId, e);
        }
    }

    @Override
    public int getFailCount(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaFailCount(userId);
            String value = stringRedisTemplate.opsForValue().get(key);
            return value != null ? Integer.parseInt(value) : 0;
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to get fail count: userId={}", userId, e);
            return 0;
        }
    }
}
