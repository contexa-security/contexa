package io.contexa.contexacore.hcad.store;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
public class RedisHCADDataStore implements HCADDataStore {

    private final RedisTemplate<String, Object> redisTemplate;
    private final Duration mfaVerifiedTtl;

    private static final Duration SESSION_TTL = Duration.ofHours(24);
    private static final Duration DEVICE_TTL = Duration.ofDays(30);
    private static final Duration DEFAULT_MFA_VERIFIED_TTL = Duration.ofHours(1);
    private static final int MAX_DEVICES = 10;

    public RedisHCADDataStore(RedisTemplate<String, Object> redisTemplate) {
        this(redisTemplate, DEFAULT_MFA_VERIFIED_TTL);
    }

    public RedisHCADDataStore(RedisTemplate<String, Object> redisTemplate, Duration mfaVerifiedTtl) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
        this.mfaVerifiedTtl = Objects.requireNonNull(mfaVerifiedTtl, "mfaVerifiedTtl");
    }

    @Override
    public Map<Object, Object> getSessionMetadata(String sessionId) {
        try {
            String key = ZeroTrustRedisKeys.sessionMetadata(sessionId);
            return redisTemplate.opsForHash().entries(key);
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to get session metadata: sessionId={}", sessionId, e);
            return new HashMap<>();
        }
    }

    @Override
    public void saveSessionMetadata(String sessionId, Map<String, Object> metadata) {
        try {
            String key = ZeroTrustRedisKeys.sessionMetadata(sessionId);
            redisTemplate.opsForHash().putAll(key, metadata);
            redisTemplate.expire(key, SESSION_TTL);
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to save session metadata: sessionId={}", sessionId, e);
        }
    }

    @Override
    public boolean isDeviceRegistered(String userId, String device) {
        try {
            String key = ZeroTrustRedisKeys.userDevices(userId);
            Double score = redisTemplate.opsForZSet().score(key, device);
            return score != null;
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to check device registration: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public void registerDevice(String userId, String device) {
        try {
            String key = ZeroTrustRedisKeys.userDevices(userId);
            double registrationOrder = System.nanoTime();
            redisTemplate.opsForZSet().add(key, device, registrationOrder);
            redisTemplate.expire(key, DEVICE_TTL);

            Long size = redisTemplate.opsForZSet().zCard(key);
            if (size != null && size > MAX_DEVICES) {
                long excess = size - MAX_DEVICES;
                redisTemplate.opsForZSet().removeRange(key, 0, excess - 1);
            }
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to register device: userId={}", userId, e);
        }
    }

    @Override
    public void recordRequest(String userId, long currentTimeMs) {
        try {
            String key = "hcad:request:counter:" + userId;
            redisTemplate.opsForZSet().add(key, Long.toString(currentTimeMs), currentTimeMs);

            long fiveMinutesAgo = currentTimeMs - (5 * 60 * 1000);
            redisTemplate.opsForZSet().removeRangeByScore(key, 0, fiveMinutesAgo);
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to record request: userId={}", userId, e);
        }
    }

    @Override
    public int getRecentRequestCount(String userId, long windowStartMs, long currentTimeMs) {
        try {
            String key = "hcad:request:counter:" + userId;
            Long count = redisTemplate.opsForZSet().count(key, windowStartMs, currentTimeMs);
            return count != null ? count.intValue() : 0;
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to get request count: userId={}", userId, e);
            return 0;
        }
    }

    @Override
    public boolean isUserRegistered(String userId) {
        try {
            String key = ZeroTrustRedisKeys.userRegistered(userId);
            return Boolean.TRUE.equals(redisTemplate.hasKey(key));
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to check user registration: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public void registerUser(String userId) {
        try {
            String key = ZeroTrustRedisKeys.userRegistered(userId);
            redisTemplate.opsForValue().set(key, "true");
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to register user: userId={}", userId, e);
        }
    }

    @Override
    public boolean isMfaVerified(String userId) {
        try {
            String key = "security:mfa:verified:" + userId;
            return Boolean.TRUE.equals(redisTemplate.hasKey(key));
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to check MFA verification: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public void markMfaVerified(String userId) {
        try {
            String key = "security:mfa:verified:" + userId;
            redisTemplate.opsForValue().set(key, "true", mfaVerifiedTtl);
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to mark MFA verified: userId={}", userId, e);
        }
    }

    @Override
    public Map<Object, Object> getHcadAnalysis(String userId) {
        try {
            String key = ZeroTrustRedisKeys.hcadAnalysis(userId);
            return redisTemplate.opsForHash().entries(key);
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to get HCAD analysis: userId={}", userId, e);
            return new HashMap<>();
        }
    }

    @Override
    public void saveHcadAnalysis(String userId, Map<String, Object> analysisData) {
        try {
            String key = ZeroTrustRedisKeys.hcadAnalysis(userId);
            redisTemplate.opsForHash().putAll(key, analysisData);
            redisTemplate.expire(key, SESSION_TTL);
        } catch (Exception e) {
            log.error("[HCADDataStore] Failed to save HCAD analysis: userId={}", userId, e);
        }
    }
}
