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
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.StoreFailures;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Redis-backed Zero Trust service. QF-57: the user's tracked session ids are kept in two keys of their own, the ids with
 * a deadline ({@link ZeroTrustRedisKeys#userSessionDeadlines}, scored by it and expiring with the last one) and those
 * without ({@link ZeroTrustRedisKeys#userUntimedSessions}, scored by their last registration, at most the per-user
 * limit). The user's session list ({@link ZeroTrustRedisKeys#userSessions}) is also the context store's list of the
 * user's sessions, whose recent requests the analysis counts; tracking does not write it, and a forced logout still
 * invalidates every id it holds. Z-16 (D-8, 2-d): neither a logout nor a forced logout removes that list or a session's
 * records in the context store; they lapse with their TTLs, as in the in-memory service.
 * <p>
 * A forced logout Redis does not take while it is away waits in {@link DeferredForcedLogouts} and is applied
 * once Redis is back. Until then the user's sessions go on, since nothing can tell them. The in-memory service has no
 * such moment: its store cannot be away.
 */
@Slf4j
public class RedisZeroTrustSecurityService extends AbstractZeroTrustSecurityService implements DisposableBean {

    /**
     * Registers an id with a deadline (KEYS[1] the deadlines, KEYS[2] the ids without one; ARGV[1] the id, ARGV[2] its
     * deadline and ARGV[3] now, in epoch milliseconds): drops the user's ids already past their deadlines, keeps the
     * later of the recorded and the given deadline, takes the id off the ids without a deadline, and lets the key
     * expire with the last deadline it holds. The numbers are read as the digits they hold, whatever the serializer.
     */
    private static final DefaultRedisScript<Long> REGISTER_TIMED_SCRIPT = new DefaultRedisScript<>(
            "local deadline = string.match(ARGV[2], '%-?%d+') "
                    + "local now = string.match(ARGV[3], '%-?%d+') "
                    + "redis.call('zremrangebyscore', KEYS[1], '-inf', '(' .. now) "
                    + "redis.call('zrem', KEYS[2], ARGV[1]) "
                    + "if tonumber(deadline) < tonumber(now) then return 0 end "
                    + "local recorded = redis.call('zscore', KEYS[1], ARGV[1]) "
                    + "if (not recorded) or tonumber(recorded) < tonumber(deadline) then "
                    + "redis.call('zadd', KEYS[1], deadline, ARGV[1]) end "
                    + "local last = redis.call('zrange', KEYS[1], -1, -1, 'WITHSCORES') "
                    + "redis.call('pexpireat', KEYS[1], string.match(last[2], '%-?%d+')) "
                    + "return 1",
            Long.class);

    /**
     * Registers an id without a deadline as the user's most recent one (KEYS[1] the ids without a deadline, KEYS[2]
     * the deadlines; ARGV[1] the id, ARGV[2] now in epoch milliseconds, ARGV[3] the per-user limit, 0 or less: none):
     * drops the user's ids past their deadlines, keeps a deadline the id has (Z-16, 2-f: a deadline never shortens),
     * and returns the least recently registered ids past the limit, which it no longer tracks without a deadline.
     */
    @SuppressWarnings("rawtypes")
    private static final DefaultRedisScript<List> REGISTER_UNTIMED_SCRIPT = new DefaultRedisScript<>(
            "local now = string.match(ARGV[2], '%-?%d+') "
                    + "local limit = tonumber(string.match(ARGV[3], '%-?%d+')) "
                    + "redis.call('zremrangebyscore', KEYS[2], '-inf', '(' .. now) "
                    + "redis.call('zadd', KEYS[1], now, ARGV[1]) "
                    + "local released = {} "
                    + "if limit > 0 then "
                    + "local excess = redis.call('zcard', KEYS[1]) - limit "
                    + "if excess > 0 then "
                    + "released = redis.call('zrange', KEYS[1], 0, excess - 1) "
                    + "redis.call('zremrangebyrank', KEYS[1], 0, excess - 1) end end "
                    + "return released",
            List.class);

    private final RedisTemplate<String, Object> redisTemplate;
    private final Clock clock;
    private final DeferredForcedLogouts deferredLogouts = new DeferredForcedLogouts();
    private volatile ContexaStores contexaStores;
    private volatile Supplier<CentralAuditFacade> audit = () -> null;

    public RedisZeroTrustSecurityService(
            RedisTemplate<String, Object> redisTemplate,
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRedisRepository) {
        this(redisTemplate, threatScoreUtil, securityZeroTrustProperties, actionRedisRepository, Clock.systemUTC());
    }

    public RedisZeroTrustSecurityService(
            RedisTemplate<String, Object> redisTemplate,
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRedisRepository,
            Clock clock) {
        super(threatScoreUtil, securityZeroTrustProperties, actionRedisRepository);
        this.redisTemplate = redisTemplate;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** The forced logouts Redis did not take are applied as soon as this gate is up again. */
    public void setContexaStores(ContexaStores contexaStores) {
        this.contexaStores = contexaStores;
        contexaStores.redis().whenBack(this::applyDeferredLogouts);
    }

    /** Where it stays on record that a forced logout waited for Redis, and that it was applied. */
    public void setAudit(Supplier<CentralAuditFacade> audit) {
        this.audit = audit;
    }

    int forcedLogoutsWaiting() {
        return deferredLogouts.size();
    }

    /** What waits in memory does not outlive the node, and an operator has to hear of it. */
    @Override
    public void destroy() {
        int waiting = deferredLogouts.size();
        if (waiting > 0) {
            log.error("[ZeroTrust] {} forced logouts were still waiting for Redis when this node stopped and will not be "
                    + "applied; the audit log names them as FORCED_LOGOUT_WAITING_FOR_REDIS.", waiting);
        }
    }

    @Autowired(required = false)
    public void setBlockingSignalBroadcaster(BlockingSignalBroadcaster broadcaster) {
        this.blockingSignalBroadcaster = broadcaster;
    }

    @Override
    protected Instant now() {
        return clock.instant();
    }

    @Override
    public void invalidateSession(String sessionId, String userId, String reason) {
        if (sessionId == null) {
            return;
        }
        try {
            writeInvalidation(sessionId, userId, reason);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to invalidate session: {}", sessionId, e);
        }
    }

    private void writeInvalidation(String sessionId, String userId, String reason) {
        String invalidKey = ZeroTrustRedisKeys.invalidSession(sessionId);

        Map<String, Object> invalidationRecord = new HashMap<>();
        invalidationRecord.put("sessionId", sessionId);
        invalidationRecord.put("userId", userId);
        invalidationRecord.put("reason", reason);
        invalidationRecord.put("timestamp", System.currentTimeMillis());

        redisTemplate.opsForValue().set(invalidKey, invalidationRecord,
                Duration.ofHours(securityZeroTrustProperties.getCache().getTtlHours()));
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
    protected void doRegisterSession(String userId, String sessionId, Instant deadline) {
        try {
            String deadlinesKey = ZeroTrustRedisKeys.userSessionDeadlines(userId);
            String untimedKey = ZeroTrustRedisKeys.userUntimedSessions(userId);
            String now = Long.toString(now().toEpochMilli());
            if (deadline != null) {
                redisTemplate.execute(REGISTER_TIMED_SCRIPT, List.of(deadlinesKey, untimedKey),
                        sessionId, Long.toString(deadline.toEpochMilli()), now);
                return;
            }
            List<?> released = redisTemplate.execute(REGISTER_UNTIMED_SCRIPT, List.of(untimedKey, deadlinesKey),
                    sessionId, now, Integer.toString(maxUntimedSessionsPerUser()));
            if (released != null) {
                for (Object releasedId : released) {
                    if (releasedId != null) {
                        releaseRegistration(releasedId.toString());
                    }
                }
            }
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to register session: userId={}, sessionId={}", userId, sessionId, e);
        }
    }

    /**
     * Stops tracking the session that logs out. Z-16 (D-8, 2-d): the context store's records of the session and its
     * list of the user's sessions stay until their TTLs, as in the in-memory service; only the session reads its own
     * records, and the user's recent requests stay counted.
     */
    @Override
    protected void doCleanupSessionData(String userId, String sessionId) {
        redisTemplate.delete(ZeroTrustRedisKeys.threatScore(userId));

        if (sessionId != null) {
            redisTemplate.opsForZSet().remove(ZeroTrustRedisKeys.userSessionDeadlines(userId), sessionId);
            redisTemplate.opsForZSet().remove(ZeroTrustRedisKeys.userUntimedSessions(userId), sessionId);
        }
    }

    /**
     * Invalidates every id of the user's session list and every tracked id not past its deadline, then stops tracking
     * them. The session list stays until its TTL (Z-16, D-8). What Redis does not take while it is away is applied once
     * it is back.
     */
    @Override
    public void invalidateAllUserSessions(String userId, String reason) {
        if (userId == null) {
            return;
        }

        try {
            endAllSessions(userId, reason);
        } catch (Exception e) {
            if (StoreFailures.isStoreFailure(e)) {
                deferredLogouts.defer(userId, reason);
                log.error("[ZeroTrust] Redis did not take the forced logout of {}: it is applied once Redis is back, and "
                        + "the user's sessions go on until then.", userId);
                recordForcedLogout(userId, reason, "FORCED_LOGOUT_WAITING_FOR_REDIS", "WAITING");
            } else {
                log.error("[ZeroTrust] Failed to invalidate all sessions for user: {}", userId, e);
            }
        }
    }

    private void endAllSessions(String userId, String reason) {
        String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
        String deadlinesKey = ZeroTrustRedisKeys.userSessionDeadlines(userId);
        String untimedKey = ZeroTrustRedisKeys.userUntimedSessions(userId);
        Set<String> sessions = new LinkedHashSet<>();
        addAll(sessions, redisTemplate.opsForSet().members(sessionsKey));
        addAll(sessions, redisTemplate.opsForZSet().rangeByScore(deadlinesKey,
                now().toEpochMilli(), Double.POSITIVE_INFINITY));
        addAll(sessions, redisTemplate.opsForZSet().range(untimedKey, 0, -1));

        for (String sessionId : sessions) {
            writeInvalidation(sessionId, userId, reason);
        }

        redisTemplate.delete(List.of(deadlinesKey, untimedKey));
    }

    /**
     * What waited for Redis, whole: the sessions and what a logout removes with them. The gate calls it as Redis
     * comes back; the sweep is there for a failure that came after the gate rose, and leaves a Redis that is down alone,
     * because its thread would wait for it.
     */
    private void applyDeferredLogouts() {
        deferredLogouts.applyAll((userId, reason) -> {
            endAllSessions(userId, reason);
            actionRepository.removeLogoutData(ZeroTrustUserKey.person(userId));
            doCleanupSessionData(userId, null);
            invalidateDecisionCache(userId);
            log.warn("[ZeroTrust] A forced logout that waited for Redis was applied: userId={}", userId);
            recordForcedLogout(userId, reason, "FORCED_LOGOUT_APPLIED_AFTER_OUTAGE", "APPLIED");
        });
    }

    @Override
    protected void doRemoveExpiredSessionData() {
        ContexaStores stores = contexaStores;
        if (deferredLogouts.size() > 0 && (stores == null || !stores.redis().isDown())) {
            applyDeferredLogouts();
        }
    }

    private void recordForcedLogout(String userId, String reason, String action, String decision) {
        CentralAuditFacade facade = audit.get();
        if (facade == null) {
            return;
        }
        try {
            facade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.SECURITY_ERROR)
                    .principalName(userId)
                    .eventSource("CORE")
                    .resourceIdentifier("ZeroTrustSecurityService")
                    .resourceUri("/errors/ZeroTrustSecurityService")
                    .action(action)
                    .decision(decision)
                    .outcome("STORE_UNAVAILABLE")
                    .reason(reason)
                    .details(Map.of("userId", userId))
                    .build());
        } catch (RuntimeException failure) {
            log.error("[ZeroTrust] The audit log did not take the record of a forced logout: userId={}, action={}", userId,
                    action, failure);
        }
    }

    private static void addAll(Set<String> target, Collection<Object> members) {
        if (members == null) {
            return;
        }
        for (Object member : members) {
            if (member != null) {
                target.add(member.toString());
            }
        }
    }
}
