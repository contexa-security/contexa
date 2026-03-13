package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.Collections;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class RedisSecurityContextDataStore implements SecurityContextDataStore {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final int MAX_SESSION_ACTIONS = 100;
    private static final Duration SESSION_ACTIONS_TTL = Duration.ofHours(24);
    private static final Duration SESSION_RISK_TTL = Duration.ofHours(1);
    private static final Duration ACTIVITY_TTL = Duration.ofMinutes(10);
    private static final Duration EVENT_PROCESSED_TTL = Duration.ofHours(24);
    private static final Duration SOAR_TTL = Duration.ofDays(7);
    private static final Duration USER_SESSIONS_TTL = Duration.ofDays(7);

    @Override
    public void addSessionAction(String sessionId, String action) {
        try {
            String key = ZeroTrustRedisKeys.sessionActions(sessionId);
            redisTemplate.opsForList().rightPush(key, action);
            redisTemplate.expire(key, SESSION_ACTIONS_TTL);

            Long size = redisTemplate.opsForList().size(key);
            if (size != null && size > MAX_SESSION_ACTIONS) {
                redisTemplate.opsForList().leftPop(key);
            }
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to add session action: sessionId={}", sessionId, e);
        }
    }

    @Override
    public List<String> getRecentSessionActions(String sessionId, int count) {
        try {
            String key = ZeroTrustRedisKeys.sessionActions(sessionId);
            List<String> actions = (List<String>) (List<?>) redisTemplate.opsForList()
                    .range(key, -count, -1);
            return actions != null ? actions : Collections.emptyList();
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session actions: sessionId={}", sessionId, e);
            return Collections.emptyList();
        }
    }

    @Override
    public void setSessionRisk(String sessionId, double riskScore) {
        try {
            String key = ZeroTrustRedisKeys.sessionRisk(sessionId);
            redisTemplate.opsForValue().set(key, riskScore, SESSION_RISK_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set session risk: sessionId={}", sessionId, e);
        }
    }

    @Override
    public void setLastRequestTime(String userId, long timestamp) {
        try {
            String key = "hcad:last:request:" + userId;
            redisTemplate.opsForValue().set(key, Long.toString(timestamp), ACTIVITY_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set last request time: userId={}", userId, e);
        }
    }

    @Override
    public Long getLastRequestTime(String userId) {
        try {
            String key = "hcad:last:request:" + userId;
            Object value = redisTemplate.opsForValue().get(key);
            if (value != null) {
                return Long.parseLong(value.toString());
            }
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get last request time: userId={}", userId, e);
        }
        return null;
    }

    @Override
    public void setPreviousPath(String userId, String path) {
        try {
            String key = "hcad:previous:path:" + userId;
            redisTemplate.opsForValue().set(key, path, ACTIVITY_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set previous path: userId={}", userId, e);
        }
    }

    @Override
    public String getPreviousPath(String userId) {
        try {
            String key = "hcad:previous:path:" + userId;
            Object value = redisTemplate.opsForValue().get(key);
            return value != null ? value.toString() : null;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get previous path: userId={}", userId, e);
            return null;
        }
    }

    @Override
    public boolean tryMarkEventAsProcessed(String eventId) {
        try {
            String key = ZeroTrustRedisKeys.eventProcessed(eventId);
            Boolean acquired = redisTemplate.opsForValue().setIfAbsent(key, "1", EVENT_PROCESSED_TTL);
            return Boolean.TRUE.equals(acquired);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to mark event as processed: eventId={}", eventId, e);
            return false;
        }
    }

    @Override
    public void storeSoarExecution(String eventId, Object data) {
        try {
            String key = ZeroTrustRedisKeys.soarExecution(eventId);
            redisTemplate.opsForValue().set(key, data, SOAR_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to store SOAR execution: eventId={}", eventId, e);
        }
    }

    @Override
    public void trackUserSession(String userId, String sessionId) {
        try {
            String key = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().add(key, sessionId);
            redisTemplate.expire(key, USER_SESSIONS_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to track user session: userId={}", userId, e);
        }
    }
}
