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

import java.time.Instant;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class RedisSecurityContextDataStore implements SecurityContextDataStore {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final int MAX_SESSION_ACTIONS = 100;
    private static final int MAX_PREVIOUS_SESSION_IDS = 20;
    private static final int MAX_WORK_PROFILE_OBSERVATIONS = 5_000;
    private static final int MAX_ROLE_SCOPE_OBSERVATIONS = 5_000;
    private static final int MAX_PERMISSION_CHANGE_OBSERVATIONS = 200;
    private static final Duration SESSION_ACTIONS_TTL = Duration.ofHours(24);
    private static final Duration SESSION_RISK_TTL = Duration.ofHours(1);
    private static final Duration ACTIVITY_TTL = Duration.ofMinutes(10);
    private static final Duration SESSION_NARRATIVE_TTL = ACTIVITY_TTL;
    /** A block can wait days for an administrator, so the facts of a stopped request are kept for a month (W5-2). */
    private static final Duration VERIFICATION_LEARNING_TTL = Duration.ofDays(30);
    /** The record of a stopped request is stored moments after its decision; a day covers a delayed store (W5-4). */
    private static final Duration VERIFICATION_OUTCOME_TTL = Duration.ofDays(1);
    private static final Duration PROMOTION_LEARNING_TTL = Duration.ofDays(30);
    private static final Duration WORK_PROFILE_TTL = Duration.ofDays(30);
    private static final Duration ROLE_SCOPE_TTL = Duration.ofDays(30);
    private static final Duration PERMISSION_CHANGE_TTL = Duration.ofDays(30);
    private static final Duration AUTHORIZATION_SCOPE_STATE_TTL = Duration.ofDays(30);
    private static final Duration EVENT_PROCESSED_TTL = Duration.ofHours(24);
    private static final Duration EVENT_PROCESSING_TTL = Duration.ofMinutes(30);
    private static final DefaultRedisScript<Long> MARK_EVENT_PROCESSED_SCRIPT = new DefaultRedisScript<>(
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
                    + "redis.call('psetex', KEYS[2], " + EVENT_PROCESSED_TTL.toMillis() + ", ARGV[1]); "
                    + "redis.call('del', KEYS[1]); return 1 else return 0 end",
            Long.class);
    private static final DefaultRedisScript<Long> RELEASE_EVENT_PROCESSING_SCRIPT = new DefaultRedisScript<>(
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
                    + "return redis.call('del', KEYS[1]) else return 0 end",
            Long.class);
    private static final DefaultRedisScript<Long> TAKE_OVER_ORPHAN_PROCESSING_SCRIPT = new DefaultRedisScript<>(
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
                    + "redis.call('psetex', KEYS[1], " + EVENT_PROCESSING_TTL.toMillis() + ", ARGV[2]); "
                    + "return 1 else return 0 end",
            Long.class);
    /**
     * Records a session's last request (KEYS[1] its time, KEYS[2] when given its path) unless a later request is
     * already recorded (N-SES-1); the stored time is read as the number it holds.
     */
    private static final DefaultRedisScript<Long> RECORD_SESSION_LAST_REQUEST_SCRIPT = new DefaultRedisScript<>(
            "local current = redis.call('get', KEYS[1]) "
                    + "if current then "
                    + "local recorded = tonumber(string.match(current, '%-?%d+')) "
                    + "local candidate = tonumber(string.match(ARGV[1], '%-?%d+')) "
                    + "if recorded and candidate and recorded > candidate then return 0 end "
                    + "end "
                    + "redis.call('psetex', KEYS[1], " + SESSION_NARRATIVE_TTL.toMillis() + ", ARGV[1]) "
                    + "if #KEYS > 1 then redis.call('psetex', KEYS[2], " + SESSION_NARRATIVE_TTL.toMillis()
                    + ", ARGV[2]) end "
                    + "return 1",
            Long.class);
    private static final String PROCESS_NODE_ID = resolveProcessNodeId();
    private static final long PROCESS_PID = ProcessHandle.current().pid();
    private static final Duration SOAR_TTL = Duration.ofDays(7);
    private static final Duration USER_SESSIONS_TTL = Duration.ofDays(7);
    private static final Duration LOGIN_FAILURE_MINIMUM_RETENTION = Duration.ofMinutes(5);
    private static final Duration LOGIN_FAILURE_EXPIRY_MARGIN = Duration.ofMinutes(5);
    private static final Duration MFA_VERIFIED_TTL = Duration.ofHours(1);
    private final AtomicLong authenticationEventSequence = new AtomicLong();
    private volatile Duration loginFailureRetention = LOGIN_FAILURE_MINIMUM_RETENTION;

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
    public void addSessionDecision(String sessionId, String decisionRecord) {
        try {
            pushBoundedList(ZeroTrustRedisKeys.sessionDecisions(sessionId), decisionRecord, SESSION_ACTIONS_TTL,
                    MAX_SESSION_ACTIONS);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to add session decision: sessionId={}", sessionId, e);
        }
    }

    @Override
    public List<String> getRecentSessionDecisions(String sessionId, int count) {
        try {
            return readStringList(ZeroTrustRedisKeys.sessionDecisions(sessionId), count);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session decisions: sessionId={}", sessionId, e);
            return null;
        }
    }

    @Override
    public void moveSessionRecords(String fromSessionId, String toSessionId) {
        if (fromSessionId == null || toSessionId == null || fromSessionId.equals(toSessionId)) {
            return;
        }
        try {
            moveList(ZeroTrustRedisKeys.sessionActions(fromSessionId), ZeroTrustRedisKeys.sessionActions(toSessionId),
                    SESSION_ACTIONS_TTL);
            moveList(ZeroTrustRedisKeys.sessionDecisions(fromSessionId), ZeroTrustRedisKeys.sessionDecisions(toSessionId),
                    SESSION_ACTIONS_TTL);
            moveList(ZeroTrustRedisKeys.sessionNarrativeActions(fromSessionId),
                    ZeroTrustRedisKeys.sessionNarrativeActions(toSessionId), SESSION_NARRATIVE_TTL);
            moveList(ZeroTrustRedisKeys.sessionProtectableAccesses(fromSessionId),
                    ZeroTrustRedisKeys.sessionProtectableAccesses(toSessionId), SESSION_NARRATIVE_TTL);
            moveList(ZeroTrustRedisKeys.sessionRequestIntervals(fromSessionId),
                    ZeroTrustRedisKeys.sessionRequestIntervals(toSessionId), SESSION_NARRATIVE_TTL);
            moveValue(ZeroTrustRedisKeys.sessionStartedAt(fromSessionId), ZeroTrustRedisKeys.sessionStartedAt(toSessionId),
                    SESSION_NARRATIVE_TTL);
            moveValue(ZeroTrustRedisKeys.sessionLastRequestTime(fromSessionId),
                    ZeroTrustRedisKeys.sessionLastRequestTime(toSessionId), SESSION_NARRATIVE_TTL);
            moveValue(ZeroTrustRedisKeys.sessionPreviousPath(fromSessionId),
                    ZeroTrustRedisKeys.sessionPreviousPath(toSessionId), SESSION_NARRATIVE_TTL);
            moveValue(ZeroTrustRedisKeys.sessionRisk(fromSessionId), ZeroTrustRedisKeys.sessionRisk(toSessionId),
                    SESSION_RISK_TTL);
            moveValue(ZeroTrustRedisKeys.sessionFirstClient(fromSessionId),
                    ZeroTrustRedisKeys.sessionFirstClient(toSessionId), SESSION_NARRATIVE_TTL);
            // The new id remembers the ids the session had, newest first (P2 correction 5).
            String previousIds = ZeroTrustRedisKeys.sessionPreviousIds(toSessionId);
            moveList(ZeroTrustRedisKeys.sessionPreviousIds(fromSessionId), previousIds, SESSION_NARRATIVE_TTL);
            redisTemplate.opsForList().leftPush(previousIds, fromSessionId);
            redisTemplate.opsForList().trim(previousIds, 0, MAX_PREVIOUS_SESSION_IDS - 1);
            redisTemplate.expire(previousIds, SESSION_NARRATIVE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to move session records to the new session id", e);
        }
    }

    /** The old id's list goes before what the new id already holds, within the same bound. */
    private void moveList(String fromKey, String toKey, Duration ttl) {
        List<Object> moved = redisTemplate.opsForList().range(fromKey, 0, -1);
        if (moved == null || moved.isEmpty()) {
            return;
        }
        List<Object> pushOrder = new ArrayList<>(moved);
        Collections.reverse(pushOrder);
        redisTemplate.opsForList().leftPushAll(toKey, pushOrder);
        redisTemplate.opsForList().trim(toKey, -MAX_SESSION_ACTIONS, -1);
        redisTemplate.expire(toKey, ttl);
        redisTemplate.delete(fromKey);
    }

    @Override
    public List<String> getSessionPreviousIds(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return List.of();
        }
        try {
            List<Object> ids = redisTemplate.opsForList().range(ZeroTrustRedisKeys.sessionPreviousIds(sessionId), 0,
                    MAX_PREVIOUS_SESSION_IDS - 1);
            return ids == null ? List.of() : ids.stream().filter(id -> id != null).map(Object::toString).toList();
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get the previous ids of a session", e);
            return List.of();
        }
    }

    /** A single value moves when the new id holds none; a value the new id already holds is the more recent one. */
    private void moveValue(String fromKey, String toKey, Duration ttl) {
        Object moved = redisTemplate.opsForValue().get(fromKey);
        if (moved == null) {
            return;
        }
        redisTemplate.opsForValue().setIfAbsent(toKey, moved, ttl);
        redisTemplate.delete(fromKey);
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
    public void addSessionNarrativeActionFamily(String sessionId, String actionFamily, long requestTimestamp) {
        addSessionNarrativeActionFamily(sessionId, SessionNarrativeEntries.encode(requestTimestamp, actionFamily));
    }

    @Override
    public List<String> getRecentSessionNarrativeActionFamilies(String sessionId, int count) {
        try {
            return SessionNarrativeEntries.recentInRequestOrder(
                    readWholeList(ZeroTrustRedisKeys.sessionNarrativeActions(sessionId)), count);
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
    public void addSessionProtectableAccess(String sessionId, String resourcePath, long requestTimestamp) {
        addSessionProtectableAccess(sessionId, SessionNarrativeEntries.encode(requestTimestamp, resourcePath));
    }

    @Override
    public List<String> getRecentSessionProtectableAccesses(String sessionId, int count) {
        try {
            return SessionNarrativeEntries.recentInRequestOrder(
                    readWholeList(ZeroTrustRedisKeys.sessionProtectableAccesses(sessionId)), count);
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
    public void addSessionRequestInterval(String sessionId, long intervalMs, long requestTimestamp) {
        try {
            pushBoundedList(ZeroTrustRedisKeys.sessionRequestIntervals(sessionId),
                    SessionNarrativeEntries.encode(requestTimestamp, Long.toString(intervalMs)), SESSION_NARRATIVE_TTL,
                    MAX_SESSION_ACTIONS);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to add session request interval: sessionId={}", sessionId, e);
        }
    }

    @Override
    public List<Long> getRecentSessionRequestIntervals(String sessionId, int count) {
        try {
            return SessionNarrativeEntries.recentIntervalsInRequestOrder(
                    readWholeList(ZeroTrustRedisKeys.sessionRequestIntervals(sessionId)), count);
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
    public void setSessionFirstClientIfAbsent(String sessionId, String firstClient) {
        if (firstClient == null) {
            return;
        }
        try {
            redisTemplate.opsForValue().setIfAbsent(ZeroTrustRedisKeys.sessionFirstClient(sessionId), firstClient,
                    SESSION_NARRATIVE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set session first client: sessionId={}", sessionId, e);
        }
    }

    @Override
    public String getSessionFirstClient(String sessionId) {
        try {
            return readStringValueAndTouch(ZeroTrustRedisKeys.sessionFirstClient(sessionId), SESSION_NARRATIVE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get session first client: sessionId={}", sessionId, e);
            return null;
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
    public void recordSessionLastRequest(String sessionId, long timestamp, String path) {
        try {
            List<String> keys = path != null
                    ? List.of(ZeroTrustRedisKeys.sessionLastRequestTime(sessionId),
                    ZeroTrustRedisKeys.sessionPreviousPath(sessionId))
                    : List.of(ZeroTrustRedisKeys.sessionLastRequestTime(sessionId));
            Object[] values = path != null ? new Object[]{Long.toString(timestamp), path}
                    : new Object[]{Long.toString(timestamp)};
            redisTemplate.execute(RECORD_SESSION_LAST_REQUEST_SCRIPT, keys, values);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to record session last request: sessionId={}", sessionId, e);
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
    public void addRoleScopeObservation(String tenantId, String scopeKey, String observation) {
        try {
            pushBoundedList(
                    ZeroTrustRedisKeys.roleScopeObservations(composeTenantScopedKey(tenantId, scopeKey)),
                    observation,
                    ROLE_SCOPE_TTL,
                    MAX_ROLE_SCOPE_OBSERVATIONS);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to add role scope observation: tenantId={}, scopeKey={}", tenantId, scopeKey, e);
        }
    }

    @Override
    public List<String> getRecentRoleScopeObservations(String tenantId, String scopeKey, int count) {
        try {
            return readStringList(
                    ZeroTrustRedisKeys.roleScopeObservations(composeTenantScopedKey(tenantId, scopeKey)),
                    count);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get role scope observations: tenantId={}, scopeKey={}", tenantId, scopeKey, e);
            return Collections.emptyList();
        }
    }

    @Override
    public void addPermissionChangeObservation(String tenantId, String userId, String observation) {
        try {
            pushBoundedList(
                    ZeroTrustRedisKeys.userPermissionChangeObservations(composeTenantScopedKey(tenantId, userId)),
                    observation,
                    PERMISSION_CHANGE_TTL,
                    MAX_PERMISSION_CHANGE_OBSERVATIONS);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to add permission change observation: tenantId={}, userId={}", tenantId, userId, e);
        }
    }

    @Override
    public List<String> getRecentPermissionChangeObservations(String tenantId, String userId, int count) {
        try {
            return readStringList(
                    ZeroTrustRedisKeys.userPermissionChangeObservations(composeTenantScopedKey(tenantId, userId)),
                    count);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get permission change observations: tenantId={}, userId={}", tenantId, userId, e);
            return Collections.emptyList();
        }
    }

    @Override
    public void setAuthorizationScopeState(String tenantId, String userId, String state) {
        try {
            redisTemplate.opsForValue().set(
                    ZeroTrustRedisKeys.userAuthorizationScopeState(composeTenantScopedKey(tenantId, userId)),
                    state,
                    AUTHORIZATION_SCOPE_STATE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to set authorization scope state: tenantId={}, userId={}", tenantId, userId, e);
        }
    }

    @Override
    public String getAuthorizationScopeState(String tenantId, String userId) {
        try {
            return readStringValueAndTouch(
                    ZeroTrustRedisKeys.userAuthorizationScopeState(composeTenantScopedKey(tenantId, userId)),
                    AUTHORIZATION_SCOPE_STATE_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to get authorization scope state: tenantId={}, userId={}", tenantId, userId, e);
            return null;
        }
    }

    @Override
    public String peekAuthorizationScopeState(String tenantId, String userId) {
        Object value = redisTemplate.opsForValue().get(
                ZeroTrustRedisKeys.userAuthorizationScopeState(composeTenantScopedKey(tenantId, userId)));
        return value == null ? null : value.toString();
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
        }
        return null;
    }

    @Override
    public void recordLoginFailure(String userId, String clientIp, long currentTimeMs) {
        if (hasText(userId)) {
            recordLoginFailureCounter(
                    ZeroTrustRedisKeys.authenticationLoginFailuresByUser(userId.trim()), currentTimeMs);
        }
        if (hasText(clientIp)) {
            recordLoginFailureCounter(
                    ZeroTrustRedisKeys.authenticationLoginFailuresByIp(clientIp.trim()), currentTimeMs);
        }
    }

    @Override
    public int getRecentLoginFailureCount(
            String userId, String clientIp, long windowStartMs, long currentTimeMs) {
        int userCount = hasText(userId)
                ? countLoginFailures(
                        ZeroTrustRedisKeys.authenticationLoginFailuresByUser(userId.trim()),
                        windowStartMs,
                        currentTimeMs)
                : 0;
        int ipCount = hasText(clientIp)
                ? countLoginFailures(
                        ZeroTrustRedisKeys.authenticationLoginFailuresByIp(clientIp.trim()),
                        windowStartMs,
                        currentTimeMs)
                : 0;
        return Math.max(userCount, ipCount);
    }

    @Override
    public boolean isMfaVerified(String userId) {
        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(
                    ZeroTrustRedisKeys.authenticationMfaVerified(userId)));
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to check MFA verification: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public void markMfaVerified(String userId) {
        markMfaVerified(userId, null);
    }

    @Override
    public void markMfaVerified(String userId, Instant verifiedAt) {
        try {
            // The value is the time of the MFA on the request clock, so that a request can say when the user last
            // completed it.
            long verifiedAtMs = verifiedAt != null ? verifiedAt.toEpochMilli() : System.currentTimeMillis();
            redisTemplate.opsForValue().set(
                    ZeroTrustRedisKeys.authenticationMfaVerified(userId),
                    String.valueOf(verifiedAtMs), MFA_VERIFIED_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to mark MFA verified: userId={}", userId, e);
        }
    }

    @Override
    public Instant getLastMfaVerifiedAt(String userId) {
        try {
            Object value = redisTemplate.opsForValue().get(ZeroTrustRedisKeys.authenticationMfaVerified(userId));
            if (value == null) {
                return null;
            }
            String text = value.toString().replace("\"", "").trim();
            return text.chars().allMatch(Character::isDigit) && !text.isEmpty()
                    ? Instant.ofEpochMilli(Long.parseLong(text))
                    : null;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to read MFA verification time: userId={}", userId, e);
            return null;
        }
    }

    @Override
    public EventProcessingClaim claimEventProcessing(String eventId) {
        return claimEventProcessingLease(eventId).claim();
    }

    @Override
    public EventProcessingLease claimEventProcessingLease(String eventId) {
        try {
            String processedKey = ZeroTrustRedisKeys.eventProcessed(eventId);
            if (redisTemplate.opsForValue().get(processedKey) != null) {
                return new EventProcessingLease(EventProcessingClaim.PROCESSED, null);
            }
            String ownerToken = newOwnerToken();
            String processingKey = ZeroTrustRedisKeys.eventProcessing(eventId);
            Boolean acquired = redisTemplate.opsForValue().setIfAbsent(
                    processingKey, ownerToken, EVENT_PROCESSING_TTL);
            if (Boolean.TRUE.equals(acquired)) {
                return new EventProcessingLease(EventProcessingClaim.ACQUIRED, ownerToken);
            }
            Object existingOwner = redisTemplate.opsForValue().get(processingKey);
            if (existingOwner != null && isLocalOrphanOwner(existingOwner.toString())) {
                Long replaced = redisTemplate.execute(
                        TAKE_OVER_ORPHAN_PROCESSING_SCRIPT,
                        List.of(processingKey),
                        existingOwner.toString(),
                        ownerToken);
                if (replaced != null && replaced == 1L) {
                    log.warn("[SecurityContextDataStore] Reclaimed orphan processing lease: eventId={}", eventId);
                    return new EventProcessingLease(EventProcessingClaim.ACQUIRED, ownerToken);
                }
            }
            return new EventProcessingLease(EventProcessingClaim.IN_FLIGHT, null);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to claim event processing: eventId={}", eventId, e);
            return new EventProcessingLease(EventProcessingClaim.IN_FLIGHT, null);
        }
    }

    @Override
    public boolean isEventProcessingOwner(String eventId, String ownerToken) {
        if (ownerToken == null || ownerToken.isBlank()) {
            return false;
        }
        try {
            Object activeOwner = redisTemplate.opsForValue().get(ZeroTrustRedisKeys.eventProcessing(eventId));
            if (ownerToken.equals(activeOwner != null ? activeOwner.toString() : null)) {
                return true;
            }
            Object completedOwner = redisTemplate.opsForValue().get(ZeroTrustRedisKeys.eventProcessed(eventId));
            return ownerToken.equals(completedOwner != null ? completedOwner.toString() : null);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to verify event processing owner: eventId={}", eventId, e);
            return false;
        }
    }

    @Override
    public void markEventProcessed(String eventId) {
        try {
            Object owner = redisTemplate.opsForValue().get(ZeroTrustRedisKeys.eventProcessing(eventId));
            if (owner != null) {
                markEventProcessed(eventId, owner.toString());
                return;
            }
            redisTemplate.opsForValue().set(ZeroTrustRedisKeys.eventProcessed(eventId), "legacy", EVENT_PROCESSED_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to mark event as processed: eventId={}", eventId, e);
        }
    }

    @Override
    public boolean markEventProcessed(String eventId, String ownerToken) {
        if (ownerToken == null || ownerToken.isBlank()) {
            return false;
        }
        try {
            Long updated = redisTemplate.execute(
                    MARK_EVENT_PROCESSED_SCRIPT,
                    List.of(ZeroTrustRedisKeys.eventProcessing(eventId), ZeroTrustRedisKeys.eventProcessed(eventId)),
                    ownerToken);
            return updated != null && updated == 1L;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to mark owned event: eventId={}", eventId, e);
            return false;
        }
    }

    @Override
    public void releaseEventProcessing(String eventId) {
        try {
            redisTemplate.delete(ZeroTrustRedisKeys.eventProcessing(eventId));
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to release event processing claim: eventId={}", eventId, e);
        }
    }

    @Override
    public boolean releaseEventProcessing(String eventId, String ownerToken) {
        if (ownerToken == null || ownerToken.isBlank()) {
            return false;
        }
        try {
            Long deleted = redisTemplate.execute(
                    RELEASE_EVENT_PROCESSING_SCRIPT,
                    List.of(ZeroTrustRedisKeys.eventProcessing(eventId)),
                    ownerToken);
            return deleted != null && deleted == 1L;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to release owned event: eventId={}", eventId, e);
            return false;
        }
    }

    private String newOwnerToken() {
        return PROCESS_NODE_ID + ":" + PROCESS_PID + ":" + UUID.randomUUID();
    }

    private boolean isLocalOrphanOwner(String ownerToken) {
        if (ownerToken == null || ownerToken.isBlank()) {
            return false;
        }
        String[] parts = ownerToken.split(":", 3);
        if (parts.length != 3 || !PROCESS_NODE_ID.equals(parts[0])) {
            return false;
        }
        try {
            long ownerPid = Long.parseLong(parts[1]);
            if (ownerPid == PROCESS_PID) {
                return false;
            }
            return ProcessHandle.of(ownerPid).map(processHandle -> !processHandle.isAlive()).orElse(true);
        } catch (NumberFormatException exception) {
            return false;
        }
    }

    private static String resolveProcessNodeId() {
        String configured = System.getenv("HOSTNAME");
        if (configured == null || configured.isBlank()) {
            configured = System.getenv("COMPUTERNAME");
        }
        String normalized = configured == null ? "local" : configured.trim();
        return normalized.replaceAll("[^A-Za-z0-9._-]", "_");
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
    public void holdVerificationLearning(String userId, String requestId, String record) {
        if (userId == null || userId.isBlank() || requestId == null || record == null) {
            return;
        }
        try {
            String key = ZeroTrustRedisKeys.verificationLearning(userId);
            redisTemplate.opsForHash().put(key, requestId, record);
            redisTemplate.expire(key, VERIFICATION_LEARNING_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to hold a request for learning after verification: userId={}",
                    userId, e);
        }
    }

    @Override
    public String takeVerificationLearning(String userId, String requestId) {
        if (userId == null || userId.isBlank() || requestId == null) {
            return null;
        }
        try {
            String key = ZeroTrustRedisKeys.verificationLearning(userId);
            Object record = redisTemplate.opsForHash().get(key, requestId);
            if (record == null || redisTemplate.opsForHash().delete(key, requestId) == 0) {
                return null;
            }
            return record.toString();
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to take a request held for learning after verification: "
                    + "userId={}", userId, e);
            return null;
        }
    }

    @Override
    public void recordVerificationOutcome(String eventId, String outcome) {
        if (eventId == null || eventId.isBlank() || outcome == null) {
            return;
        }
        try {
            redisTemplate.opsForValue().set(ZeroTrustRedisKeys.verificationOutcome(eventId), outcome,
                    VERIFICATION_OUTCOME_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to keep the outcome of a verification: eventId={}", eventId, e);
        }
    }

    @Override
    public String verificationOutcome(String eventId) {
        if (eventId == null || eventId.isBlank()) {
            return null;
        }
        try {
            Object outcome = redisTemplate.opsForValue().get(ZeroTrustRedisKeys.verificationOutcome(eventId));
            return outcome != null ? outcome.toString() : null;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to read the outcome of a verification: eventId={}", eventId, e);
            return null;
        }
    }

    @Override
    public void holdPromotionLearning(String userId, String requestId, String record) {
        if (userId == null || userId.isBlank() || requestId == null || record == null) {
            return;
        }
        try {
            String key = ZeroTrustRedisKeys.promotionLearning(userId);
            redisTemplate.opsForHash().put(key, requestId, record);
            redisTemplate.expire(key, PROMOTION_LEARNING_TTL);
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to hold a request for promotion: userId={}", userId, e);
        }
    }

    @Override
    public Map<String, String> promotionLearning(String userId) {
        if (userId == null || userId.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, String> held = new LinkedHashMap<>();
            redisTemplate.opsForHash().entries(ZeroTrustRedisKeys.promotionLearning(userId))
                    .forEach((requestId, record) -> held.put(requestId.toString(), record.toString()));
            return held;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to read the requests held for promotion: userId={}",
                    userId, e);
            return Map.of();
        }
    }

    @Override
    public void removePromotionLearning(String userId, Collection<String> requestIds) {
        if (userId == null || userId.isBlank() || requestIds == null || requestIds.isEmpty()) {
            return;
        }
        try {
            redisTemplate.opsForHash().delete(ZeroTrustRedisKeys.promotionLearning(userId), requestIds.toArray());
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to remove promoted requests: userId={}", userId, e);
        }
    }

    @Override
    public void deleteUserData(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        List<String> keys = new ArrayList<>(List.of(
                ZeroTrustRedisKeys.verificationLearning(userId),
                ZeroTrustRedisKeys.promotionLearning(userId),
                ZeroTrustRedisKeys.userLastRequestTime(userId),
                ZeroTrustRedisKeys.userPreviousPath(userId),
                ZeroTrustRedisKeys.authenticationMfaVerified(userId),
                ZeroTrustRedisKeys.authenticationLoginFailuresByUser(userId.trim()),
                ZeroTrustRedisKeys.userSessions(userId),
                ZeroTrustRedisKeys.userWorkProfileObservations(userId),
                ZeroTrustRedisKeys.userPermissionChangeObservations(userId),
                ZeroTrustRedisKeys.userAuthorizationScopeState(userId)));
        String anyTenantScope = "*::" + ZeroTrustRedisKeys.globLiteral(userId);
        keys.addAll(scanKeys(ZeroTrustRedisKeys.userWorkProfileObservations(anyTenantScope)));
        keys.addAll(scanKeys(ZeroTrustRedisKeys.userPermissionChangeObservations(anyTenantScope)));
        keys.addAll(scanKeys(ZeroTrustRedisKeys.userAuthorizationScopeState(anyTenantScope)));
        redisTemplate.delete(keys);
    }

    private List<String> scanKeys(String pattern) {
        List<String> keys = new ArrayList<>();
        try (Cursor<String> cursor = redisTemplate.scan(ScanOptions.scanOptions().match(pattern).count(500).build())) {
            cursor.forEachRemaining(keys::add);
        }
        return keys;
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

    @Override
    public Set<String> getUserSessions(String userId) {
        try {
            Set<Object> members = redisTemplate.opsForSet().members(ZeroTrustRedisKeys.userSessions(userId));
            Set<String> sessions = new TreeSet<>();
            if (members != null) {
                for (Object member : members) {
                    if (member != null) {
                        sessions.add(member.toString());
                    }
                }
            }
            return sessions;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to read user sessions: userId={}", userId, e);
            return null;
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

    /**
     * Sets how long login failures stay countable: the longest window any reader queries, at least five minutes. Older
     * failures are trimmed when a new one arrives, and the key outlives the window by a margin.
     */
    public void setLoginFailureRetention(Duration retention) {
        if (retention != null && retention.compareTo(LOGIN_FAILURE_MINIMUM_RETENTION) > 0) {
            loginFailureRetention = retention;
        }
    }

    @Override
    public Integer findRecentLoginFailures(String userId, long windowStartMs, long currentTimeMs) {
        if (!hasText(userId)) {
            return null;
        }
        try {
            Long count = redisTemplate.opsForZSet().count(
                    ZeroTrustRedisKeys.authenticationLoginFailuresByUser(userId.trim()), windowStartMs, currentTimeMs);
            return count != null ? count.intValue() : null;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to count login failures: userId={}", userId, e);
            return null;
        }
    }

    private void recordLoginFailureCounter(String key, long currentTimeMs) {
        try {
            Duration retention = loginFailureRetention;
            String member = currentTimeMs + ":" + authenticationEventSequence.incrementAndGet();
            redisTemplate.opsForZSet().add(key, member, currentTimeMs);
            redisTemplate.opsForZSet().removeRangeByScore(key, 0, currentTimeMs - retention.toMillis());
            redisTemplate.expire(key, retention.plus(LOGIN_FAILURE_EXPIRY_MARGIN));
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to record login failure: key={}", key, e);
        }
    }

    private int countLoginFailures(String key, long windowStartMs, long currentTimeMs) {
        try {
            Long count = redisTemplate.opsForZSet().count(key, windowStartMs, currentTimeMs);
            return count != null ? count.intValue() : 0;
        } catch (Exception e) {
            log.error("[SecurityContextDataStore] Failed to count login failures: key={}", key, e);
            return 0;
        }
    }

    private static boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    /** A session narrative list whole (at most {@link #MAX_SESSION_ACTIONS} entries), to be read in request order. */
    private List<Object> readWholeList(String key) {
        List<Object> values = redisTemplate.opsForList().range(key, 0, -1);
        return values == null ? List.of() : values;
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
        return composeTenantScopedKey(tenantId, userId);
    }

    private String composeTenantScopedKey(String tenantId, String key) {
        if (tenantId == null || tenantId.isBlank()) {
            return key;
        }
        return tenantId + "::" + key;
    }
}
