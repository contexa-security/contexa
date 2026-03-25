package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class RedisSecurityContextDataStore implements SecurityContextDataStore {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final int MAX_SESSION_ACTIONS = 100;
    private static final int MAX_WORK_PROFILE_OBSERVATIONS = 5_000;
    private static final Duration SESSION_ACTIONS_TTL = Duration.ofHours(24);
    private static final Duration SESSION_RISK_TTL = Duration.ofHours(1);
    private static final Duration ACTIVITY_TTL = Duration.ofMinutes(10);
    private static final Duration SESSION_NARRATIVE_TTL = ACTIVITY_TTL;
    private static final Duration WORK_PROFILE_TTL = Duration.ofDays(30);
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
            return readStringList(key, count);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session actions: sessionId={}", sessionId, e);
            return Collections.emptyList();
        }
    }

    @Override
    public void addSessionNarrativeActionFamily(String sessionId, String actionFamily) {
        try {
            pushBoundedList(ZeroTrustRedisKeys.sessionNarrativeActions(sessionId), actionFamily, SESSION_NARRATIVE_TTL, MAX_SESSION_ACTIONS);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to add session narrative action family: sessionId={}", sessionId, e);
        }
    }

    @Override
    public List<String> getRecentSessionNarrativeActionFamilies(String sessionId, int count) {
        try {
            return readStringList(ZeroTrustRedisKeys.sessionNarrativeActions(sessionId), count);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session narrative action families: sessionId={}", sessionId, e);
            return Collections.emptyList();
        }
    }

    @Override
    public void addSessionProtectableAccess(String sessionId, String resourcePath) {
        try {
            pushBoundedList(ZeroTrustRedisKeys.sessionProtectableAccesses(sessionId), resourcePath, SESSION_NARRATIVE_TTL, MAX_SESSION_ACTIONS);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to add session protectable access: sessionId={}", sessionId, e);
        }
    }

    @Override
    public List<String> getRecentSessionProtectableAccesses(String sessionId, int count) {
        try {
            return readStringList(ZeroTrustRedisKeys.sessionProtectableAccesses(sessionId), count);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session protectable accesses: sessionId={}", sessionId, e);
            return Collections.emptyList();
        }
    }

    @Override
    public void addSessionRequestInterval(String sessionId, long intervalMs) {
        try {
            pushBoundedList(ZeroTrustRedisKeys.sessionRequestIntervals(sessionId), intervalMs, SESSION_NARRATIVE_TTL, MAX_SESSION_ACTIONS);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to add session request interval: sessionId={}", sessionId, e);
        }
    }

    @Override
    public List<Long> getRecentSessionRequestIntervals(String sessionId, int count) {
        try {
            String key = ZeroTrustRedisKeys.sessionRequestIntervals(sessionId);
            List<Object> values = redisTemplate.opsForList().range(key, -count, -1);
            if (values == null || values.isEmpty()) {
                return Collections.emptyList();
            }
            List<Long> intervals = new ArrayList<>(values.size());
            for (Object value : values) {
                if (value == null) {
                    continue;
                }
                intervals.add(Long.parseLong(value.toString()));
            }
            return intervals;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session request intervals: sessionId={}", sessionId, e);
            return Collections.emptyList();
        }
    }

    @Override
    public void setSessionStartedAt(String sessionId, long timestamp) {
        try {
            redisTemplate.opsForValue().set(
                    ZeroTrustRedisKeys.sessionStartedAt(sessionId),
                    Long.toString(timestamp),
                    SESSION_NARRATIVE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set session startedAt: sessionId={}", sessionId, e);
        }
    }

    @Override
    public Long getSessionStartedAt(String sessionId) {
        try {
            return readLongValueAndTouch(ZeroTrustRedisKeys.sessionStartedAt(sessionId), SESSION_NARRATIVE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session startedAt: sessionId={}", sessionId, e);
            return null;
        }
    }

    @Override
    public void setSessionLastRequestTime(String sessionId, long timestamp) {
        try {
            redisTemplate.opsForValue().set(
                    ZeroTrustRedisKeys.sessionLastRequestTime(sessionId),
                    Long.toString(timestamp),
                    SESSION_NARRATIVE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set session last request time: sessionId={}", sessionId, e);
        }
    }

    @Override
    public Long getSessionLastRequestTime(String sessionId) {
        try {
            return readLongValueAndTouch(ZeroTrustRedisKeys.sessionLastRequestTime(sessionId), SESSION_NARRATIVE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session last request time: sessionId={}", sessionId, e);
            return null;
        }
    }

    @Override
    public void setSessionPreviousPath(String sessionId, String path) {
        try {
            redisTemplate.opsForValue().set(
                    ZeroTrustRedisKeys.sessionPreviousPath(sessionId),
                    path,
                    SESSION_NARRATIVE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set session previous path: sessionId={}", sessionId, e);
        }
    }

    @Override
    public String getSessionPreviousPath(String sessionId) {
        try {
            return readStringValueAndTouch(ZeroTrustRedisKeys.sessionPreviousPath(sessionId), SESSION_NARRATIVE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session previous path: sessionId={}", sessionId, e);
            return null;
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
    public void addWorkProfileObservation(String tenantId, String userId, String observation) {
        try {
            pushBoundedList(
                    ZeroTrustRedisKeys.userWorkProfileObservations(composeWorkProfileScopeKey(tenantId, userId)),
                    observation,
                    WORK_PROFILE_TTL,
                    MAX_WORK_PROFILE_OBSERVATIONS);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to add work profile observation: tenantId={}, userId={}", tenantId, userId, e);
        }
    }

    @Override
    public List<String> getRecentWorkProfileObservations(String tenantId, String userId, int count) {
        try {
            return readStringList(
                    ZeroTrustRedisKeys.userWorkProfileObservations(composeWorkProfileScopeKey(tenantId, userId)),
                    count);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get work profile observations: tenantId={}, userId={}", tenantId, userId, e);
            return Collections.emptyList();
        }
    }

    @Override
    public void setLastRequestTime(String userId, long timestamp) {
        try {
            String key = ZeroTrustRedisKeys.userLastRequestTime(userId);
            redisTemplate.opsForValue().set(key, Long.toString(timestamp), ACTIVITY_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set last request time: userId={}", userId, e);
        }
    }

    @Override
    public Long getLastRequestTime(String userId) {
        try {
            String key = ZeroTrustRedisKeys.userLastRequestTime(userId);
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
            String key = ZeroTrustRedisKeys.userPreviousPath(userId);
            redisTemplate.opsForValue().set(key, path, ACTIVITY_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set previous path: userId={}", userId, e);
        }
    }

    @Override
    public String getPreviousPath(String userId) {
        try {
            String key = ZeroTrustRedisKeys.userPreviousPath(userId);
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

    private void pushBoundedList(String key, Object value, Duration ttl, int maxSize) {
        redisTemplate.opsForList().rightPush(key, value);
        redisTemplate.expire(key, ttl);

        Long size = redisTemplate.opsForList().size(key);
        if (size != null && size > maxSize) {
            redisTemplate.opsForList().leftPop(key);
        }
    }

    private List<String> readStringList(String key, int count) {
        List<Object> values = redisTemplate.opsForList().range(key, -count, -1);
        if (values == null || values.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> results = new ArrayList<>(values.size());
        for (Object value : values) {
            if (value != null) {
                results.add(value.toString());
            }
        }
        return results;
    }

    private Long readLongValueAndTouch(String key, Duration ttl) {
        Object value = redisTemplate.opsForValue().get(key);
        if (value == null) {
            return null;
        }
        redisTemplate.expire(key, ttl);
        return Long.parseLong(value.toString());
    }

    private String readStringValueAndTouch(String key, Duration ttl) {
        Object value = redisTemplate.opsForValue().get(key);
        if (value == null) {
            return null;
        }
        redisTemplate.expire(key, ttl);
        return value.toString();
    }

    private String composeWorkProfileScopeKey(String tenantId, String userId) {
        if (tenantId == null || tenantId.isBlank()) {
            return userId;
        }
        return tenantId + "::" + userId;
    }
}
