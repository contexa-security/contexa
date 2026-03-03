package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
public class RedisZeroTrustSecurityService extends AbstractZeroTrustSecurityService {

    private final RedisTemplate<String, Object> redisTemplate;

    public RedisZeroTrustSecurityService(
            RedisTemplate<String, Object> redisTemplate,
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRedisRepository) {
        super(threatScoreUtil, securityZeroTrustProperties, actionRedisRepository);
        this.redisTemplate = redisTemplate;
    }

    @Autowired(required = false)
    public void setBlockingSignalBroadcaster(BlockingSignalBroadcaster broadcaster) {
        this.blockingSignalBroadcaster = broadcaster;
    }

    @Override
    public void invalidateSession(String sessionId, String userId, String reason) {
        if (sessionId == null) {
            return;
        }
        try {
            String invalidKey = ZeroTrustRedisKeys.invalidSession(sessionId);

            Map<String, Object> invalidationRecord = new HashMap<>();
            invalidationRecord.put("sessionId", sessionId);
            invalidationRecord.put("userId", userId);
            invalidationRecord.put("reason", reason);
            invalidationRecord.put("timestamp", System.currentTimeMillis());

            redisTemplate.opsForValue().set(invalidKey, invalidationRecord,
                    Duration.ofHours(securityZeroTrustProperties.getCache().getTtlHours()));

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to invalidate session: {}", sessionId, e);
        }
    }

    @Override
    public boolean isSessionInvalidated(String sessionId) {
        if (sessionId == null) {
            return false;
        }

        try {
            String invalidKey = ZeroTrustRedisKeys.invalidSession(sessionId);
            return redisTemplate.hasKey(invalidKey);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to check session invalidation: {}", sessionId, e);
            return false;
        }
    }

    @Override
    protected void doRegisterSession(String userId, String sessionId) {
        try {
            String key = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().add(key, sessionId);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to register session: userId={}, sessionId={}", userId, sessionId, e);
        }
    }

    @Override
    protected void doCleanupSessionData(String userId, String sessionId) {
        redisTemplate.delete(ZeroTrustRedisKeys.threatScore(userId));

        if (sessionId != null) {
            redisTemplate.delete(ZeroTrustRedisKeys.sessionActions(sessionId));
            redisTemplate.delete(ZeroTrustRedisKeys.sessionMetadata(sessionId));
            redisTemplate.delete(ZeroTrustRedisKeys.sessionRisk(sessionId));

            String userSessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().remove(userSessionsKey, sessionId);
        }
    }

    @Override
    public void invalidateAllUserSessions(String userId, String reason) {
        if (userId == null) {
            return;
        }

        try {
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            Set<Object> sessions = redisTemplate.opsForSet().members(sessionsKey);

            if (sessions != null) {
                for (Object sessionObj : sessions) {
                    invalidateSession(sessionObj.toString(), userId, reason);
                }
            }

            redisTemplate.delete(sessionsKey);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to invalidate all sessions for user: {}", userId, e);
        }
    }
}
