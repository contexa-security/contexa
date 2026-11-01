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

import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory Zero Trust service. Z-16 (2-a to 2-f), as the Redis service: an invalidation lasts
 * {@code contexa.security.zerotrust.cache.ttl-hours} unless a TTL is given, and only its TTL ends it; a forced logout
 * reaches every tracked id and every id of the context store's list of the user's sessions, which neither a logout nor
 * a forced logout changes; the container's end of a session leaves the id to its deadline. Z-16 (N-1): the
 * invalidations, the deadlines and each user's ids without one are {@link ExpiringKeySpace}s.
 */
public class InMemoryZeroTrustSecurityService extends AbstractZeroTrustSecurityService {

    private static final Duration DEFAULT_INVALIDATION_TTL = Duration.ofHours(24);
    /**
     * An id without a deadline never expires: its expiry, past any clock, is the order of its registration, so the
     * per-user limit releases the least recently registered first.
     */
    private static final long UNTIMED_ORDER_BASE = Long.MAX_VALUE / 2;

    private final ExpiringKeySpace<Boolean> invalidatedSessions;
    /** Every identifier tracked for a user; a forced logout invalidates them all. */
    private final Map<String, Set<String>> userSessions = new ConcurrentHashMap<>();
    /** Each identifier registered with a deadline, until it is certainly dead. */
    private final ExpiringKeySpace<Boolean> trackUntil;
    /**
     * QF-57: each user's identifiers registered without a deadline. Changed and read only while the user's entry of
     * {@link #userSessions} is being computed.
     */
    private final Map<String, UntimedSessions> untimedSessions = new ConcurrentHashMap<>();
    private final AtomicLong untimedOrder = new AtomicLong(UNTIMED_ORDER_BASE);
    private final Clock clock;
    private final SecurityContextDataStore securityContextDataStore;

    public InMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster) {
        this(threatScoreUtil, securityZeroTrustProperties, actionRepository, blockingSignalBroadcaster, null,
                invalidationTtlOf(securityZeroTrustProperties), Clock.systemUTC());
    }

    public InMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            Duration invalidationTtl) {
        this(threatScoreUtil, securityZeroTrustProperties, actionRepository,
                blockingSignalBroadcaster, invalidationTtl, Clock.systemUTC());
    }

    public InMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            Duration invalidationTtl,
            Clock clock) {
        this(threatScoreUtil, securityZeroTrustProperties, actionRepository, blockingSignalBroadcaster, null,
                invalidationTtl, clock);
    }

    /**
     * Z-16 (2-a, 2-c): an invalidation lasts {@code contexa.security.zerotrust.cache.ttl-hours}, and a forced logout
     * also reaches the ids of the context store's list of the user's sessions (none without a store).
     */
    public InMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            SecurityContextDataStore securityContextDataStore,
            Clock clock) {
        this(threatScoreUtil, securityZeroTrustProperties, actionRepository, blockingSignalBroadcaster,
                securityContextDataStore, invalidationTtlOf(securityZeroTrustProperties), clock);
    }

    private InMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            SecurityContextDataStore securityContextDataStore,
            Duration invalidationTtl,
            Clock clock) {
        super(threatScoreUtil, securityZeroTrustProperties, actionRepository);
        this.blockingSignalBroadcaster = blockingSignalBroadcaster;
        this.securityContextDataStore = securityContextDataStore;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.invalidatedSessions = ExpiringKeySpace.<Boolean>builder(clock)
                .ttl(Objects.requireNonNull(invalidationTtl, "invalidationTtl"))
                .build();
        this.trackUntil = ExpiringKeySpace.<Boolean>builder(clock).build();
    }

    /** The invalidation TTL the Redis service applies: the configured cache TTL, a day without settings. */
    private static Duration invalidationTtlOf(SecurityZeroTrustProperties properties) {
        return properties != null && properties.getCache() != null
                ? Duration.ofHours(properties.getCache().getTtlHours()) : DEFAULT_INVALIDATION_TTL;
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
        invalidatedSessions.put(sessionId, Boolean.TRUE);
    }

    @Override
    public boolean isSessionInvalidated(String sessionId) {
        if (sessionId == null) {
            return false;
        }
        return invalidatedSessions.containsKey(sessionId);
    }

    /**
     * Tracks the identifier for the user. With a deadline it is kept until the latest deadline given for it; without
     * one it becomes the user's most recently registered identifier without a deadline, and the least recently
     * registered past the per-user limit are released (QF-57).
     */
    @Override
    protected void doRegisterSession(String userId, String sessionId, Instant deadline) {
        int limit = maxUntimedSessionsPerUser();
        List<String> released = new ArrayList<>();
        // Changed inside compute so the sweep cannot drop the user's entry between its creation and this add.
        userSessions.compute(userId, (user, sessions) -> {
            Set<String> tracked = sessions != null ? sessions : ConcurrentHashMap.newKeySet();
            tracked.add(sessionId);
            if (deadline != null) {
                long deadlineMs = deadline.toEpochMilli();
                trackUntil.atomically(sessionId, slot -> {
                    slot.setUntil(Boolean.TRUE, Math.max(slot.expiresAtMs(), deadlineMs));
                    return null;
                });
                forgetUntimed(user, sessionId);
                return tracked;
            }
            UntimedSessions untimed = untimedSessions.computeIfAbsent(user, ignored -> new UntimedSessions(clock, limit));
            long order = untimedOrder.incrementAndGet();
            untimed.ids.atomically(sessionId, slot -> {
                slot.setUntil(sessionId, order);
                return null;
            });
            for (String evicted : untimed.takeReleased()) {
                if (!trackUntil.containsKey(evicted)) {
                    tracked.remove(evicted);
                }
                released.add(evicted);
            }
            return tracked;
        });
        released.forEach(this::releaseRegistration);
    }

    /**
     * Releases invalidation marks past their TTL, identifiers past their deadlines and users without tracked
     * sessions. An identifier with a live deadline or one of the user's identifiers without a deadline is never
     * dropped, so forced logout keeps reaching every live session.
     */
    @Override
    protected void doRemoveExpiredSessionData() {
        invalidatedSessions.removeExpired();
        trackUntil.removeExpired();
        for (String userId : userSessions.keySet()) {
            userSessions.computeIfPresent(userId, (user, sessions) -> {
                UntimedSessions untimed = untimedSessions.get(user);
                sessions.removeIf(sessionId -> !trackUntil.containsKey(sessionId)
                        && (untimed == null || !untimed.ids.containsKey(sessionId)));
                if (!sessions.isEmpty()) {
                    return sessions;
                }
                untimedSessions.remove(user);
                return null;
            });
        }
    }

    boolean tracksSession(String sessionId) {
        return trackUntil.holds(sessionId)
                || userSessions.values().stream().anyMatch(sessions -> sessions.contains(sessionId));
    }

    /**
     * Stops tracking the session that logs out. Its invalidation, if any, stays until its TTL (Z-16, 2-b), and the
     * context store's records stay until theirs (D-8), as in the Redis service.
     */
    @Override
    protected void doCleanupSessionData(String userId, String sessionId) {
        if (sessionId != null) {
            userSessions.computeIfPresent(userId, (user, sessions) -> {
                sessions.remove(sessionId);
                forgetUntimed(user, sessionId);
                return sessions;
            });
        }
    }

    /**
     * Invalidates every tracked id of the user and every id of the context store's list of the user's sessions, then
     * stops tracking the user. The list itself stays until its TTL, its recent requests still counted (Z-16, 2-c, D-8).
     */
    @Override
    public void invalidateAllUserSessions(String userId, String reason) {
        if (userId == null) {
            return;
        }

        Set<String> sessions = new LinkedHashSet<>();
        userSessions.computeIfPresent(userId, (user, tracked) -> {
            sessions.addAll(tracked);
            untimedSessions.remove(user);
            return null;
        });
        if (securityContextDataStore != null) {
            Set<String> listed = securityContextDataStore.getUserSessions(userId);
            if (listed != null) {
                sessions.addAll(listed);
            }
        }
        for (String sessionId : sessions) {
            invalidateSession(sessionId, userId, reason);
        }
    }

    /** Takes the identifier off the user's identifiers without a deadline; called while the user's entry computes. */
    private void forgetUntimed(String userId, String sessionId) {
        UntimedSessions untimed = untimedSessions.get(userId);
        if (untimed != null && untimed.ids.remove(sessionId) != null && untimed.ids.size() == 0) {
            untimedSessions.remove(userId);
        }
    }

    /**
     * A user's identifiers without a deadline, bounded by the per-user limit (0 or less: none), and those the limit
     * released at the registration that is being made.
     */
    private static final class UntimedSessions {

        private final List<String> released = new ArrayList<>();
        private final ExpiringKeySpace<String> ids;

        private UntimedSessions(Clock clock, int limit) {
            ExpiringKeySpace.Builder<String> builder = ExpiringKeySpace.<String>builder(clock).onRemoved(released::add);
            this.ids = (limit > 0 ? builder.bound(limit) : builder).build();
        }

        /** The identifiers released since the last call. */
        private List<String> takeReleased() {
            List<String> taken = List.copyOf(released);
            released.clear();
            return taken;
        }
    }
}
