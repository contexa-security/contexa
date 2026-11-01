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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * The in-memory twin of {@link RedisSecurityContextDataStore}. Z-16: each kind of record is an {@link ExpiringKeySpace}
 * that keeps, extends on a read and forgets its keys as the Redis store does its keys of the same kind; only what needs
 * several nodes differs (the Lua scripts are single compute calls, an orphan claim of another process is not taken
 * over). The bounds on keys are for the memory of the JVM, which Redis leaves to its own memory limit.
 */
public class InMemorySecurityContextDataStore implements SecurityContextDataStore, ExpiringStateStore {

    private static final int MAX_SESSION_ACTIONS = 100;
    private static final int MAX_VERIFICATION_OUTCOMES = 10_000;
    private static final int MAX_STOPPED_REQUESTS = 20;
    private static final int MAX_PREVIOUS_SESSION_IDS = 20;
    private static final int MAX_PERMISSION_CHANGE_OBSERVATIONS = 200;
    private static final int MAX_PROCESSED_EVENTS = 50_000;
    private static final int MAX_SOAR_EXECUTIONS = 10_000;
    private static final int MAX_SESSION_ENTRIES = 10_000;
    /** QF-42: the default budget of the held learning records is a tenth of the maximum heap, within these bounds. */
    private static final int DEFAULT_HELD_LEARNING_HEAP_SHARE_DIVISOR = 10;
    private static final long MIN_DEFAULT_HELD_LEARNING_BYTES = 16L * 1024 * 1024;
    private static final long MAX_DEFAULT_HELD_LEARNING_BYTES = 1024L * 1024 * 1024;
    /** How far the release order may outgrow twice the held records before its stale entries are dropped. */
    private static final int HELD_LEARNING_ORDER_SLACK = 1_024;

    private static final Duration DEFAULT_EVENT_PROCESSED_TTL = Duration.ofHours(24);
    private static final Duration DEFAULT_SOAR_TTL = Duration.ofDays(7);
    private static final Duration DEFAULT_USER_SESSIONS_TTL = Duration.ofDays(7);
    private static final Duration MFA_VERIFIED_TTL = Duration.ofHours(1);
    private static final Duration LOGIN_FAILURE_MINIMUM_RETENTION = Duration.ofMinutes(5);
    /** A request a filter stopped waits for the step-up while the challenge that stopped it is in force (N-LRN-3). */
    private static final Duration STOPPED_REQUEST_TTL = ZeroTrustAction.CHALLENGE.getDefaultTtl();
    /** A verified stopped request is sent again under the ALLOW the step-up writes (N-LRN-3). */
    private static final Duration VERIFIED_STOPPED_REQUEST_TTL = ZeroTrustAction.ALLOW.getDefaultTtl();
    /**
     * QF-42, Z-16: how long RedisSecurityContextDataStore keeps each kind of key after its last write, the same
     * values (the shared contract test holds both stores to them): a session's actions and decisions, a session's
     * narrative and activity, a session's risk, a user's last request, and what is learned (observations,
     * authorization states, held requests). This class does not read the Redis store's constants: that class needs
     * Redis on the class path, which a standalone deployment may not have.
     */
    private static final Duration SESSION_RECORDS_TTL = Duration.ofHours(24);
    private static final Duration SESSION_ACTIVITY_TTL = Duration.ofMinutes(10);
    private static final Duration SESSION_RISK_TTL = Duration.ofHours(1);
    private static final Duration USER_ACTIVITY_TTL = Duration.ofMinutes(10);
    private static final Duration LEARNING_TTL = Duration.ofDays(30);
    /** Z-16 D-5: the record of a stopped request is stored moments after its decision; a day covers a delayed store. */
    private static final Duration VERIFICATION_OUTCOME_TTL = Duration.ofDays(1);
    /** Z-16 D-6: a processing claim is a lease; a claim not released or completed within it can be claimed again. */
    private static final Duration EVENT_PROCESSING_TTL = Duration.ofMinutes(30);

    private final Duration eventProcessedTtl;
    private final Duration soarTtl;
    private final Duration userSessionsTtl;
    private final Clock clock;

    public InMemorySecurityContextDataStore() {
        this(DEFAULT_EVENT_PROCESSED_TTL, DEFAULT_SOAR_TTL, DEFAULT_USER_SESSIONS_TTL, Clock.systemUTC());
    }

    public InMemorySecurityContextDataStore(Duration eventProcessedTtl,
                                            Duration soarTtl,
                                            Duration userSessionsTtl) {
        this(eventProcessedTtl, soarTtl, userSessionsTtl, Clock.systemUTC());
    }

    public InMemorySecurityContextDataStore(Duration eventProcessedTtl,
                                            Duration soarTtl,
                                            Duration userSessionsTtl,
                                            Clock clock) {
        this.eventProcessedTtl = Objects.requireNonNull(eventProcessedTtl, "eventProcessedTtl");
        this.soarTtl = Objects.requireNonNull(soarTtl, "soarTtl");
        this.userSessionsTtl = Objects.requireNonNull(userSessionsTtl, "userSessionsTtl");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.sessionActions = sessionScopedSpace(SESSION_RECORDS_TTL);
        this.sessionDecisions = sessionScopedSpace(SESSION_RECORDS_TTL);
        this.sessionNarrativeActionFamilies = sessionScopedSpace(SESSION_ACTIVITY_TTL);
        this.sessionProtectableAccesses = sessionScopedSpace(SESSION_ACTIVITY_TTL);
        this.sessionRequestIntervals = sessionScopedSpace(SESSION_ACTIVITY_TTL);
        this.sessionStartedAt = sessionScopedSpace(SESSION_ACTIVITY_TTL);
        this.sessionLastRequestTimes = sessionScopedSpace(SESSION_ACTIVITY_TTL);
        this.sessionPreviousPaths = sessionScopedSpace(SESSION_ACTIVITY_TTL);
        this.sessionFirstClients = sessionScopedSpace(SESSION_ACTIVITY_TTL);
        this.sessionPreviousIds = sessionScopedSpace(SESSION_ACTIVITY_TTL);
        this.sessionRisks = sessionScopedSpace(SESSION_RISK_TTL);
        this.lastRequestTimes = userActivitySpace();
        this.previousPaths = userActivitySpace();
        this.workProfileObservations = learningSpace(value -> {
        });
        this.roleScopeObservations = learningSpace(value -> {
        });
        this.permissionChangeObservations = learningSpace(value -> {
        });
        this.authorizationScopeStates = learningSpace(value -> {
        });
        this.verificationLearning = learningSpace(this::releaseHeldRecords);
        this.promotionLearning = learningSpace(this::releaseHeldRecords);
        this.stoppedRequests = ExpiringKeySpace.<StoppedRequests>builder(clock).build();
        this.mfaVerifiedAt = ExpiringKeySpace.<Long>builder(clock).ttl(MFA_VERIFIED_TTL).build();
        this.accountDeletions = ExpiringKeySpace.<Instant>builder(clock).build();
        this.userSessions = ExpiringKeySpace.<Set<String>>builder(clock).ttl(userSessionsTtl)
                .bound(MAX_SESSION_ENTRIES).build();
        this.processingEventOwners = ExpiringKeySpace.<String>builder(clock).ttl(EVENT_PROCESSING_TTL).build();
        this.processedEvents = ExpiringKeySpace.<String>builder(clock).ttl(eventProcessedTtl)
                .bound(MAX_PROCESSED_EVENTS).build();
        this.soarExecutions = ExpiringKeySpace.<Object>builder(clock).ttl(soarTtl).bound(MAX_SOAR_EXECUTIONS).build();
        this.verificationOutcomes = ExpiringKeySpace.<String>builder(clock).ttl(VERIFICATION_OUTCOME_TTL)
                .bound(MAX_VERIFICATION_OUTCOMES).build();
        this.sessionScopedSpaces = List.of(sessionStartedAt, sessionActions, sessionDecisions,
                sessionNarrativeActionFamilies, sessionProtectableAccesses, sessionRequestIntervals, sessionRisks,
                sessionLastRequestTimes, sessionPreviousPaths, sessionPreviousIds, sessionFirstClients);
        this.spaces = List.of(sessionActions, sessionDecisions, sessionNarrativeActionFamilies,
                sessionProtectableAccesses, sessionRequestIntervals, sessionStartedAt, sessionLastRequestTimes,
                sessionPreviousPaths, sessionFirstClients, sessionPreviousIds, sessionRisks, lastRequestTimes,
                previousPaths, workProfileObservations, roleScopeObservations, permissionChangeObservations,
                authorizationScopeStates, verificationLearning, promotionLearning, stoppedRequests, mfaVerifiedAt,
                accountDeletions, userSessions, processingEventOwners, processedEvents, soarExecutions,
                verificationOutcomes);
    }

    private final ExpiringKeySpace<List<String>> sessionActions;
    private final ExpiringKeySpace<List<String>> sessionNarrativeActionFamilies;
    private final ExpiringKeySpace<List<String>> sessionDecisions;
    private final ExpiringKeySpace<List<String>> sessionProtectableAccesses;
    /** Each interval with the time of its request when known (N-SES-1). */
    private final ExpiringKeySpace<List<String>> sessionRequestIntervals;
    private final ExpiringKeySpace<List<String>> workProfileObservations;
    /** docs/agent A3-8: the scopes whose learning an operator quarantined. */
    private final Set<String> quarantinedLearning = ConcurrentHashMap.newKeySet();
    private final ExpiringKeySpace<List<String>> roleScopeObservations;
    private final ExpiringKeySpace<List<String>> permissionChangeObservations;
    private final ExpiringKeySpace<Double> sessionRisks;
    private final ExpiringKeySpace<Long> sessionStartedAt;
    private final ExpiringKeySpace<Long> sessionLastRequestTimes;
    private final ExpiringKeySpace<String> sessionPreviousPaths;
    private final ExpiringKeySpace<String> sessionFirstClients;
    /** The facts of each user's requests a restriction stopped, by request id (W5-2). */
    private final ExpiringKeySpace<Map<String, HeldRecord>> verificationLearning;
    private final ExpiringKeySpace<Map<String, HeldRecord>> promotionLearning;
    /** The requests a filter stopped under each user's challenge, by method and URI (N-LRN-3). */
    private final ExpiringKeySpace<StoppedRequests> stoppedRequests;
    /** The ids a session had before its id was replaced, newest first (P2 correction 5). */
    private final ExpiringKeySpace<List<String>> sessionPreviousIds;
    private final ExpiringKeySpace<String> authorizationScopeStates;
    private final ExpiringKeySpace<Long> lastRequestTimes;
    private final ExpiringKeySpace<String> previousPaths;
    private final ConcurrentHashMap<String, ConcurrentSkipListMap<Long, String>> loginFailureCounters =
            new ConcurrentHashMap<>();
    /** When each user last completed MFA, on the request clock, while the mark lasts. */
    private final ExpiringKeySpace<Long> mfaVerifiedAt;
    private volatile Duration loginFailureRetention = LOGIN_FAILURE_MINIMUM_RETENTION;
    /** BR-C14: how many work profile and role scope observations each scope keeps. */
    private volatile int observationCapacity = DEFAULT_OBSERVATION_CAPACITY;
    /**
     * QF-42: the bytes the records held for verification and promotion learning may take together, counted at two bytes
     * a character, and what they take now; past the budget the records held the longest ago go first, whoever holds
     * them.
     */
    private volatile long heldLearningBudgetBytes = defaultHeldLearningBudgetBytes(Runtime.getRuntime().maxMemory());
    private final AtomicLong heldLearningBytes = new AtomicLong();
    private final AtomicLong heldLearningRecords = new AtomicLong();
    private final AtomicLong heldLearningSequence = new AtomicLong();
    /** One entry for every record held, in the order they were held; see {@link HeldEntry}. */
    private final ConcurrentLinkedQueue<HeldEntry> heldLearningOrder = new ConcurrentLinkedQueue<>();
    private final AtomicLong heldLearningOrderEntries = new AtomicLong();
    /** Taken by the releases over the budget and by the pass that drops stale entries from the order. */
    private final ReentrantLock heldLearningReleaseLock = new ReentrantLock();
    private final AtomicLong authenticationEventSequence = new AtomicLong();
    /** Guards the moves of an event between its processing claim and its processed mark. */
    private final Object eventProcessingLock = new Object();
    /** The owner of each event in processing, for {@link #EVENT_PROCESSING_TTL} (Z-16 D-6). */
    private final ExpiringKeySpace<String> processingEventOwners;
    /** The owner of each event processed, or {@code legacy}. */
    private final ExpiringKeySpace<String> processedEvents;
    private final ExpiringKeySpace<Object> soarExecutions;
    private final ExpiringKeySpace<String> verificationOutcomes;
    private final ExpiringKeySpace<Set<String>> userSessions;
    /** The users whose account was deleted and when, until the deletion's retention passes (Q-15). */
    private final ExpiringKeySpace<Instant> accountDeletions;
    /** The spaces keyed by session id; a session evicted for their bound leaves all of them together. */
    private final List<ExpiringKeySpace<?>> sessionScopedSpaces;
    private final List<ExpiringKeySpace<?>> spaces;

    /** A user's stopped requests, verified once the user passed the step-up (N-LRN-3). */
    private record StoppedRequests(Set<String> signatures, boolean verified) {
    }

    /** A record held for learning and its place among all the records held (QF-42). */
    private record HeldRecord(String value, long sequence) {

        private long bytes() {
            return heldRecordBytes(value);
        }
    }

    /**
     * QF-42: a held record's place in the release order: the space and key it is held under, its request id, and the
     * sequence of the {@link HeldRecord} it was made for. Once that record is no longer held (taken, replaced, removed
     * with its user, expired, or released for a bound) the entry is stale and releases nothing.
     */
    private record HeldEntry(ExpiringKeySpace<Map<String, HeldRecord>> held, String userId, String requestId,
                             long sequence) {
    }

    @Override
    public void addSessionAction(String sessionId, String action) {
        appendToStringSequence(sessionActions, sessionId, action, MAX_SESSION_ACTIONS);
    }

    @Override
    public List<String> getRecentSessionActions(String sessionId, int count) {
        return recentStringSequence(sessionActions.get(sessionId), count);
    }

    @Override
    public void addSessionDecision(String sessionId, String decisionRecord) {
        appendToStringSequence(sessionDecisions, sessionId, decisionRecord, MAX_SESSION_ACTIONS);
    }

    @Override
    public List<String> getRecentSessionDecisions(String sessionId, int count) {
        return recentStringSequence(sessionDecisions.get(sessionId), count);
    }

    @Override
    public void moveSessionRecords(String fromSessionId, String toSessionId) {
        if (fromSessionId == null || toSessionId == null || fromSessionId.equals(toSessionId)) {
            return;
        }
        moveSequence(sessionActions, fromSessionId, toSessionId);
        moveSequence(sessionDecisions, fromSessionId, toSessionId);
        moveSequence(sessionNarrativeActionFamilies, fromSessionId, toSessionId);
        moveSequence(sessionProtectableAccesses, fromSessionId, toSessionId);
        moveSequence(sessionRequestIntervals, fromSessionId, toSessionId);
        moveValue(sessionStartedAt, fromSessionId, toSessionId);
        moveValue(sessionLastRequestTimes, fromSessionId, toSessionId);
        moveValue(sessionPreviousPaths, fromSessionId, toSessionId);
        moveValue(sessionRisks, fromSessionId, toSessionId);
        moveValue(sessionFirstClients, fromSessionId, toSessionId);
        List<String> earlier = sessionPreviousIds.remove(fromSessionId);
        sessionPreviousIds.compute(toSessionId, (key, current) -> {
            List<String> ids = new ArrayList<>();
            ids.add(fromSessionId);
            if (earlier != null) {
                ids.addAll(earlier);
            }
            if (current != null) {
                ids.addAll(current);
            }
            return List.copyOf(ids.subList(0, Math.min(ids.size(), MAX_PREVIOUS_SESSION_IDS)));
        });
    }

    @Override
    public List<String> getSessionPreviousIds(String sessionId) {
        if (sessionId == null) {
            return List.of();
        }
        List<String> ids = sessionPreviousIds.get(sessionId);
        return ids == null ? List.of() : ids;
    }

    @Override
    public void setSessionFirstClientIfAbsent(String sessionId, String firstClient) {
        if (sessionId != null && firstClient != null) {
            // Z-16 D-2: as SET NX EX, a client already kept stays with its expiry.
            sessionFirstClients.putIfAbsent(sessionId, firstClient);
        }
    }

    @Override
    public String getSessionFirstClient(String sessionId) {
        return sessionId == null ? null : sessionFirstClients.getAndRefresh(sessionId);
    }

    private static <T> void moveSequence(ExpiringKeySpace<List<T>> space, String fromKey, String toKey) {
        List<T> moved = space.remove(fromKey);
        if (moved == null || moved.isEmpty()) {
            return;
        }
        space.compute(toKey, (key, current) -> {
            List<T> merged = Collections.synchronizedList(new ArrayList<>());
            synchronized (moved) {
                merged.addAll(moved);
            }
            if (current != null) {
                synchronized (current) {
                    merged.addAll(current);
                }
            }
            while (merged.size() > MAX_SESSION_ACTIONS) {
                merged.remove(0);
            }
            return merged;
        });
    }

    /**
     * A single value moves when the new id holds none; a value the new id already holds is the more recent one and
     * keeps its expiry (Z-16 D-4, as SET NX EX).
     */
    private static <T> void moveValue(ExpiringKeySpace<T> space, String fromKey, String toKey) {
        T moved = space.remove(fromKey);
        if (moved != null) {
            space.putIfAbsent(toKey, moved);
        }
    }

    @Override
    public void addSessionNarrativeActionFamily(String sessionId, String actionFamily) {
        appendToStringSequence(sessionNarrativeActionFamilies, sessionId, actionFamily, MAX_SESSION_ACTIONS);
    }

    @Override
    public void addSessionNarrativeActionFamily(String sessionId, String actionFamily, long requestTimestamp) {
        appendToStringSequence(sessionNarrativeActionFamilies, sessionId,
                SessionNarrativeEntries.encode(requestTimestamp, actionFamily), MAX_SESSION_ACTIONS);
    }

    @Override
    public List<String> getRecentSessionNarrativeActionFamilies(String sessionId, int count) {
        return SessionNarrativeEntries.recentInRequestOrder(copyOf(sessionNarrativeActionFamilies.get(sessionId)), count);
    }

    @Override
    public void addSessionProtectableAccess(String sessionId, String resourcePath) {
        appendToStringSequence(sessionProtectableAccesses, sessionId, resourcePath, MAX_SESSION_ACTIONS);
    }

    @Override
    public void addSessionProtectableAccess(String sessionId, String resourcePath, long requestTimestamp) {
        appendToStringSequence(sessionProtectableAccesses, sessionId,
                SessionNarrativeEntries.encode(requestTimestamp, resourcePath), MAX_SESSION_ACTIONS);
    }

    @Override
    public List<String> getRecentSessionProtectableAccesses(String sessionId, int count) {
        return SessionNarrativeEntries.recentInRequestOrder(copyOf(sessionProtectableAccesses.get(sessionId)), count);
    }

    @Override
    public void addSessionRequestInterval(String sessionId, long intervalMs) {
        appendToStringSequence(sessionRequestIntervals, sessionId, Long.toString(intervalMs), MAX_SESSION_ACTIONS);
    }

    @Override
    public void addSessionRequestInterval(String sessionId, long intervalMs, long requestTimestamp) {
        appendToStringSequence(sessionRequestIntervals, sessionId,
                SessionNarrativeEntries.encode(requestTimestamp, Long.toString(intervalMs)), MAX_SESSION_ACTIONS);
    }

    @Override
    public List<Long> getRecentSessionRequestIntervals(String sessionId, int count) {
        return SessionNarrativeEntries.recentIntervalsInRequestOrder(copyOf(sessionRequestIntervals.get(sessionId)), count);
    }

    @Override
    public void setSessionStartedAt(String sessionId, long timestamp) {
        sessionStartedAt.put(sessionId, timestamp);
    }

    @Override
    public Long getSessionStartedAt(String sessionId) {
        return sessionStartedAt.getAndRefresh(sessionId);
    }

    @Override
    public void setSessionLastRequestTime(String sessionId, long timestamp) {
        sessionLastRequestTimes.put(sessionId, timestamp);
    }

    @Override
    public Long getSessionLastRequestTime(String sessionId) {
        return sessionLastRequestTimes.getAndRefresh(sessionId);
    }

    @Override
    public void setSessionPreviousPath(String sessionId, String path) {
        sessionPreviousPaths.put(sessionId, path);
    }

    @Override
    public String getSessionPreviousPath(String sessionId) {
        return sessionPreviousPaths.getAndRefresh(sessionId);
    }

    @Override
    public void recordSessionLastRequest(String sessionId, long timestamp, String path) {
        sessionLastRequestTimes.atomically(sessionId, slot -> {
            Long recorded = slot.value();
            if (recorded != null && recorded > timestamp) {
                // Z-16 D-3: a later request is recorded, so nothing changes, nor how long the records are kept.
                return null;
            }
            slot.set(timestamp);
            if (path != null) {
                sessionPreviousPaths.put(sessionId, path);
            }
            return null;
        });
    }

    @Override
    public void setSessionRisk(String sessionId, double riskScore) {
        sessionRisks.put(sessionId, riskScore);
    }

    @Override
    public void addWorkProfileObservation(String tenantId, String userId, String observation) {
        appendToStringSequence(
                workProfileObservations,
                composeWorkProfileKey(tenantId, userId),
                observation,
                observationCapacity);
    }

    @Override
    public List<String> getRecentWorkProfileObservations(String tenantId, String userId, int count) {
        return recentStringSequence(workProfileObservations.get(composeWorkProfileKey(tenantId, userId)), count);
    }

    @Override
    public void addRoleScopeObservation(String tenantId, String scopeKey, String observation) {
        appendToStringSequence(
                roleScopeObservations,
                composeTenantScopedKey(tenantId, scopeKey),
                observation,
                observationCapacity);
    }

    @Override
    public List<String> getRecentRoleScopeObservations(String tenantId, String scopeKey, int count) {
        return recentStringSequence(roleScopeObservations.get(composeTenantScopedKey(tenantId, scopeKey)), count);
    }

    @Override
    public void addPermissionChangeObservation(String tenantId, String userId, String observation) {
        appendToStringSequence(
                permissionChangeObservations,
                composeTenantScopedKey(tenantId, userId),
                observation,
                MAX_PERMISSION_CHANGE_OBSERVATIONS);
    }

    @Override
    public List<String> getRecentPermissionChangeObservations(String tenantId, String userId, int count) {
        return recentStringSequence(permissionChangeObservations.get(composeTenantScopedKey(tenantId, userId)), count);
    }

    @Override
    public void setAuthorizationScopeState(String tenantId, String userId, String state) {
        authorizationScopeStates.put(composeTenantScopedKey(tenantId, userId), state);
    }

    @Override
    public String getAuthorizationScopeState(String tenantId, String userId) {
        return authorizationScopeStates.getAndRefresh(composeTenantScopedKey(tenantId, userId));
    }

    @Override
    public String peekAuthorizationScopeState(String tenantId, String userId) {
        return authorizationScopeStates.get(composeTenantScopedKey(tenantId, userId));
    }

    @Override
    public void setLastRequestTime(String userId, long timestamp) {
        lastRequestTimes.put(userId, timestamp);
    }

    @Override
    public Long getLastRequestTime(String userId) {
        return lastRequestTimes.get(userId);
    }

    @Override
    public void setPreviousPath(String userId, String path) {
        previousPaths.put(userId, path);
    }

    @Override
    public String getPreviousPath(String userId) {
        return previousPaths.get(userId);
    }

    @Override
    public void recordLoginFailure(String userId, String clientIp, long currentTimeMs) {
        if (hasText(userId)) {
            recordLoginFailureCounter("user:" + userId.trim(), currentTimeMs);
        }
        if (hasText(clientIp)) {
            recordLoginFailureCounter("ip:" + clientIp.trim(), currentTimeMs);
        }
    }

    @Override
    public int getRecentLoginFailureCount(
            String userId, String clientIp, long windowStartMs, long currentTimeMs) {
        int userCount = hasText(userId)
                ? countLoginFailures("user:" + userId.trim(), windowStartMs, currentTimeMs)
                : 0;
        int ipCount = hasText(clientIp)
                ? countLoginFailures("ip:" + clientIp.trim(), windowStartMs, currentTimeMs)
                : 0;
        return Math.max(userCount, ipCount);
    }

    @Override
    public boolean isMfaVerified(String userId) {
        return mfaVerifiedAt.containsKey(userId);
    }

    @Override
    public void markMfaVerified(String userId) {
        markMfaVerified(userId, null);
    }

    @Override
    public void markMfaVerified(String userId, Instant verifiedAt) {
        mfaVerifiedAt.put(userId, verifiedAt != null ? verifiedAt.toEpochMilli() : clock.millis());
    }

    @Override
    public Instant getLastMfaVerifiedAt(String userId) {
        Long verifiedAt = mfaVerifiedAt.get(userId);
        return verifiedAt == null ? null : Instant.ofEpochMilli(verifiedAt);
    }

    @Override
    public void holdVerificationLearning(String userId, String requestId, String record) {
        if (userId == null || requestId == null || record == null) {
            return;
        }
        holdLearningRecord(verificationLearning, userId, requestId, record);
    }

    @Override
    public String takeVerificationLearning(String userId, String requestId) {
        if (userId == null || requestId == null) {
            return null;
        }
        String[] taken = new String[1];
        // As HDEL, taking a record leaves how long the user's other records are kept.
        verificationLearning.computeIfPresent(userId, (key, held) -> {
            HeldRecord removed = held.remove(requestId);
            releaseHeldRecord(removed);
            taken[0] = removed != null ? removed.value() : null;
            return held.isEmpty() ? null : held;
        });
        return taken[0];
    }

    @Override
    public void holdStoppedRequest(String userId, String requestSignature) {
        if (userId == null || requestSignature == null) {
            return;
        }
        stoppedRequests.atomically(userId, slot -> {
            StoppedRequests held = slot.value();
            if (held == null || held.verified()) {
                // A stop after a verification belongs to a new challenge, so the stopped requests are kept anew.
                slot.set(new StoppedRequests(Set.of(requestSignature), false), STOPPED_REQUEST_TTL);
            } else if (!held.signatures().contains(requestSignature)
                    && held.signatures().size() < MAX_STOPPED_REQUESTS) {
                Set<String> signatures = new LinkedHashSet<>(held.signatures());
                signatures.add(requestSignature);
                slot.keep(new StoppedRequests(signatures, false));
            }
            return null;
        });
    }

    @Override
    public void verifyStoppedRequests(String userId, String learnedRequestSignature) {
        if (userId == null) {
            return;
        }
        stoppedRequests.atomically(userId, slot -> {
            StoppedRequests held = slot.value();
            if (held == null || held.verified()) {
                return null;
            }
            Set<String> signatures = new LinkedHashSet<>(held.signatures());
            if (learnedRequestSignature != null) {
                signatures.remove(learnedRequestSignature);
            }
            if (signatures.isEmpty()) {
                slot.delete();
            } else {
                slot.set(new StoppedRequests(signatures, true), VERIFIED_STOPPED_REQUEST_TTL);
            }
            return null;
        });
    }

    @Override
    public boolean takeVerifiedStoppedRequest(String userId, String requestSignature) {
        if (userId == null || requestSignature == null) {
            return false;
        }
        return Boolean.TRUE.equals(stoppedRequests.atomically(userId, slot -> {
            StoppedRequests held = slot.value();
            if (held == null || !held.verified() || !held.signatures().contains(requestSignature)) {
                return false;
            }
            slot.delete();
            return true;
        }));
    }

    @Override
    public void recordVerificationOutcome(String eventId, String outcome) {
        if (eventId == null || outcome == null) {
            return;
        }
        verificationOutcomes.put(eventId, outcome);
    }

    @Override
    public String verificationOutcome(String eventId) {
        return eventId == null ? null : verificationOutcomes.get(eventId);
    }

    @Override
    public void recordAccountDeletion(String userId, Instant deletedAt, Duration retention) {
        if (userId == null || deletedAt == null || retention == null) {
            return;
        }
        accountDeletions.put(userId, deletedAt, retention);
    }

    @Override
    public Instant accountDeletedAt(String userId) {
        return userId == null ? null : accountDeletions.get(userId);
    }

    @Override
    public void holdPromotionLearning(String userId, String requestId, String record) {
        if (userId == null || requestId == null || record == null) {
            return;
        }
        holdLearningRecord(promotionLearning, userId, requestId, record);
    }

    @Override
    public Map<String, String> promotionLearning(String userId) {
        if (userId == null) {
            return Map.of();
        }
        AtomicReference<Map<String, String>> copy = new AtomicReference<>(Map.of());
        promotionLearning.computeIfPresent(userId, (key, held) -> {
            Map<String, String> records = new LinkedHashMap<>();
            held.forEach((requestId, record) -> records.put(requestId, record.value()));
            copy.set(records);
            return held;
        });
        return copy.get();
    }

    @Override
    public void removePromotionLearning(String userId, Collection<String> requestIds) {
        if (userId == null || requestIds == null || requestIds.isEmpty()) {
            return;
        }
        promotionLearning.computeIfPresent(userId, (key, held) -> {
            requestIds.forEach(requestId -> releaseHeldRecord(held.remove(requestId)));
            return held.isEmpty() ? null : held;
        });
    }

    @Override
    public void setLearningQuarantined(String scope, boolean quarantined) {
        if (scope == null || scope.isBlank()) {
            return;
        }
        if (quarantined) {
            quarantinedLearning.add(scope);
        } else {
            quarantinedLearning.remove(scope);
        }
    }

    @Override
    public boolean learningQuarantined(String scope) {
        return scope != null && quarantinedLearning.contains(scope);
    }

    @Override
    public Set<String> learningQuarantineScopes() {
        return Set.copyOf(quarantinedLearning);
    }

    @Override
    public int deleteAgentLearning(String agentId) {
        if (agentId == null || agentId.isBlank()) {
            return 0;
        }
        String suffix = LearningSubject.AGENT_KEY + agentId;
        return workProfileObservations.removeIf(key -> key.endsWith(suffix));
    }

    @Override
    public void deleteUserData(String userId) {
        if (userId == null) {
            return;
        }
        releaseHeldRecords(verificationLearning.remove(userId));
        releaseHeldRecords(promotionLearning.remove(userId));
        stoppedRequests.remove(userId);
        String tenantScopedSuffix = "::" + userId;
        Predicate<String> usersKeys = key -> key.equals(userId) || key.endsWith(tenantScopedSuffix);
        for (ExpiringKeySpace<?> perUser : List.of(
                workProfileObservations, permissionChangeObservations, authorizationScopeStates)) {
            perUser.removeIf(usersKeys);
        }
        // QF-29: the user's held requests are kept within each tenant.
        promotionLearning.removeIf(key -> key.endsWith(tenantScopedSuffix), this::releaseHeldRecords);
        // docs/agent A3-1: what the agents acting for the user learned, under their learning keys in every tenant.
        String agentKeys = userId + LearningSubject.AGENT_KEY;
        Predicate<String> agentsKeys = key -> key.startsWith(agentKeys) || key.contains("::" + agentKeys);
        promotionLearning.removeIf(agentsKeys, this::releaseHeldRecords);
        // docs/agent F-6 (CF-27): and the authorization state the agents' requests are compared with.
        for (ExpiringKeySpace<?> perAgent : List.of(
                workProfileObservations, permissionChangeObservations, authorizationScopeStates)) {
            perAgent.removeIf(agentsKeys);
        }
        lastRequestTimes.remove(userId);
        previousPaths.remove(userId);
        mfaVerifiedAt.remove(userId);
        loginFailureCounters.remove("user:" + userId.trim());
        userSessions.remove(userId);
    }

    @Override
    public EventProcessingClaim claimEventProcessing(String eventId) {
        return claimEventProcessingLease(eventId).claim();
    }

    @Override
    public EventProcessingLease claimEventProcessingLease(String eventId) {
        synchronized (eventProcessingLock) {
            if (processedEvents.containsKey(eventId)) {
                return new EventProcessingLease(EventProcessingClaim.PROCESSED, null);
            }
            String ownerToken = UUID.randomUUID().toString();
            if (!processingEventOwners.putIfAbsent(eventId, ownerToken)) {
                return new EventProcessingLease(EventProcessingClaim.IN_FLIGHT, null);
            }
            return new EventProcessingLease(EventProcessingClaim.ACQUIRED, ownerToken);
        }
    }

    @Override
    public boolean isEventProcessingOwner(String eventId, String ownerToken) {
        if (ownerToken == null || ownerToken.isBlank()) {
            return false;
        }
        synchronized (eventProcessingLock) {
            return ownerToken.equals(processingEventOwners.get(eventId))
                    || ownerToken.equals(processedEvents.get(eventId));
        }
    }

    @Override
    public void markEventProcessed(String eventId) {
        synchronized (eventProcessingLock) {
            String ownerToken = processingEventOwners.remove(eventId);
            processedEvents.put(eventId, ownerToken != null ? ownerToken : "legacy");
        }
    }

    @Override
    public boolean markEventProcessed(String eventId, String ownerToken) {
        synchronized (eventProcessingLock) {
            if (ownerToken == null || !ownerToken.equals(processingEventOwners.get(eventId))) {
                return false;
            }
            processingEventOwners.remove(eventId);
            processedEvents.put(eventId, ownerToken);
            return true;
        }
    }

    @Override
    public void releaseEventProcessing(String eventId) {
        synchronized (eventProcessingLock) {
            processingEventOwners.remove(eventId);
        }
    }

    @Override
    public boolean releaseEventProcessing(String eventId, String ownerToken) {
        synchronized (eventProcessingLock) {
            return ownerToken != null && processingEventOwners.remove(eventId, ownerToken);
        }
    }

    @Override
    public void storeSoarExecution(String eventId, Object data) {
        if (eventId == null || data == null) {
            return;
        }
        soarExecutions.put(eventId, data);
    }

    @Override
    public void trackUserSession(String userId, String sessionId) {
        userSessions.compute(userId, (key, sessions) -> {
            Set<String> tracked = sessions != null ? sessions : ConcurrentHashMap.newKeySet();
            tracked.add(sessionId);
            return tracked;
        });
    }

    @Override
    public Set<String> getUserSessions(String userId) {
        if (userId == null) {
            return Set.of();
        }
        Set<String> sessions = userSessions.get(userId);
        return sessions == null ? Set.of() : Set.copyOf(sessions);
    }

    Object peekSoarExecution(String eventId) {
        return soarExecutions.get(eventId);
    }

    Set<String> peekUserSessions(String userId) {
        Set<String> sessions = userSessions.get(userId);
        return sessions == null ? Collections.emptySet() : Collections.unmodifiableSet(sessions);
    }

    /**
     * Sets how long login failures stay countable: the longest window any reader queries, at least five minutes. Older
     * failures are trimmed whenever a new one arrives.
     */
    public void setLoginFailureRetention(Duration retention) {
        if (retention != null && retention.compareTo(LOGIN_FAILURE_MINIMUM_RETENTION) > 0) {
            loginFailureRetention = retention;
        }
    }

    /**
     * BR-C14: how many work profile and role scope observations each scope keeps, at least one;
     * {@link #DEFAULT_OBSERVATION_CAPACITY} unless set.
     */
    public void setObservationCapacity(int capacity) {
        this.observationCapacity = Math.max(1, capacity);
    }

    @Override
    public int observationCapacity() {
        return observationCapacity;
    }

    /**
     * QF-42: the bytes the records held for verification and promotion learning may take together, counted at two
     * bytes a character; not positive, {@link #defaultHeldLearningBudgetBytes(long) the budget derived from the maximum
     * heap}. Past it the records held the longest ago are released, whoever holds them: their later verification or
     * promotion is not learned, and no decision changes.
     */
    public void setHeldLearningBudgetBytes(long budgetBytes) {
        heldLearningBudgetBytes = budgetBytes > 0
                ? budgetBytes : defaultHeldLearningBudgetBytes(Runtime.getRuntime().maxMemory());
        releaseHeldLearningOverBudget();
    }

    /** The bytes the held learning records may take together (QF-42). */
    public long heldLearningBudgetBytes() {
        return heldLearningBudgetBytes;
    }

    /**
     * QF-42: the default budget of the held learning records for a maximum heap of {@code maxHeapBytes}: a tenth of it,
     * between 16 MiB and 1 GiB. A 512 MiB heap gives 51.2 MiB, 2 GiB 204.8 MiB, 8 GiB 819.2 MiB, 10 GiB or more and a
     * JVM without a heap limit 1 GiB. The records are counted at two bytes a character, so records of Latin-1
     * characters, which the JVM keeps at one byte a character, take half the budget in character data.
     */
    static long defaultHeldLearningBudgetBytes(long maxHeapBytes) {
        return Math.max(MIN_DEFAULT_HELD_LEARNING_BYTES,
                Math.min(MAX_DEFAULT_HELD_LEARNING_BYTES, maxHeapBytes / DEFAULT_HELD_LEARNING_HEAP_SHARE_DIVISOR));
    }

    /** The bytes the held learning records take now, as counted against the budget (QF-42). */
    long heldLearningBytes() {
        return heldLearningBytes.get();
    }

    /** The entries of the release order of the held learning records, stale ones included (QF-42). */
    long heldLearningOrderEntries() {
        return heldLearningOrderEntries.get();
    }

    /**
     * Releases every record no read can return any more, as the Redis store's keys expire (Z-16: the reads already
     * ignore them), keeps every bounded space within its bound for the writes that left it to the sweep, and releases
     * the login failures past the longest queried window.
     */
    @Override
    public void removeExpiredEntries() {
        spaces.forEach(ExpiringKeySpace::removeExpired);
        removeExpiredLoginFailures(clock.millis());
        releaseHeldLearningOverBudget();
    }

    /**
     * Holds a record under the user and request id in place of the one held under them, keeping all held records
     * within the budget (QF-42); as the Redis store, a user holds any number of records (Z-16 D-7). A record larger
     * than the whole budget is not held, and the one it would replace goes, so it releases no other record.
     */
    private void holdLearningRecord(ExpiringKeySpace<Map<String, HeldRecord>> target, String userId, String requestId,
                                    String record) {
        boolean withinBudget = heldRecordBytes(record) <= heldLearningBudgetBytes;
        BiFunction<String, Map<String, HeldRecord>, Map<String, HeldRecord>> hold = (key, held) -> {
            Map<String, HeldRecord> records = held != null ? held : new LinkedHashMap<>();
            releaseHeldRecord(records.remove(requestId));
            if (withinBudget) {
                HeldRecord kept = new HeldRecord(record, heldLearningSequence.incrementAndGet());
                records.put(requestId, kept);
                heldLearningBytes.addAndGet(kept.bytes());
                heldLearningRecords.incrementAndGet();
                heldLearningOrder.add(new HeldEntry(target, userId, requestId, kept.sequence()));
                heldLearningOrderEntries.incrementAndGet();
            }
            return records.isEmpty() ? null : records;
        };
        if (withinBudget) {
            // HSET then EXPIRE.
            target.compute(userId, hold);
        } else {
            // Only the record it would replace goes, as an HDEL, which leaves the key's expiry.
            target.computeIfPresent(userId, hold);
        }
        releaseHeldLearningOverBudget();
    }

    /** The bytes a held record is counted at: two a character, its size as UTF-16 (QF-42). */
    private static long heldRecordBytes(String record) {
        return 2L * record.length();
    }

    /** Takes a record that left its map out of the held bytes; called once for each record, where it is removed. */
    private void releaseHeldRecord(HeldRecord record) {
        if (record != null) {
            heldLearningBytes.addAndGet(-record.bytes());
            heldLearningRecords.decrementAndGet();
        }
    }

    /** Takes all the records of a user's map that left its store out of the held bytes. */
    private void releaseHeldRecords(Map<String, HeldRecord> records) {
        if (records != null) {
            records.values().forEach(this::releaseHeldRecord);
        }
    }

    /**
     * QF-42: releases the records held the longest ago, whoever holds them, until the held records take no more than
     * the budget. Each record held has one entry in the order and an entry is taken once, so all the releases together
     * take at most as many entries as records were held: a constant a write on average, no pass over the users. A
     * released record's later verification or promotion is not learned; no decision changes.
     */
    private void releaseHeldLearningOverBudget() {
        if (heldLearningBytes.get() > heldLearningBudgetBytes) {
            heldLearningReleaseLock.lock();
            try {
                while (heldLearningBytes.get() > heldLearningBudgetBytes) {
                    HeldEntry oldest = heldLearningOrder.poll();
                    if (oldest == null) {
                        break;
                    }
                    heldLearningOrderEntries.decrementAndGet();
                    oldest.held().computeIfPresent(oldest.userId(), (key, records) -> {
                        if (holds(records, oldest)) {
                            releaseHeldRecord(records.remove(oldest.requestId()));
                        }
                        return records.isEmpty() ? null : records;
                    });
                }
            } finally {
                heldLearningReleaseLock.unlock();
            }
        }
        dropStaleHeldLearningEntries();
    }

    /**
     * Drops the entries of records no longer held once the order has more than twice as many entries as there are
     * records held (and {@link #HELD_LEARNING_ORDER_SLACK} more). Each held record has one entry, so at least half the
     * entries a pass looks at go: the passes take a constant a write on average and keep the order within twice the
     * held records.
     */
    private void dropStaleHeldLearningEntries() {
        if (heldLearningOrderEntries.get() <= 2 * heldLearningRecords.get() + HELD_LEARNING_ORDER_SLACK
                || !heldLearningReleaseLock.tryLock()) {
            return;
        }
        try {
            Iterator<HeldEntry> entries = heldLearningOrder.iterator();
            while (entries.hasNext()) {
                HeldEntry entry = entries.next();
                boolean[] held = new boolean[1];
                entry.held().computeIfPresent(entry.userId(), (key, records) -> {
                    held[0] = holds(records, entry);
                    return records;
                });
                if (!held[0]) {
                    entries.remove();
                    heldLearningOrderEntries.decrementAndGet();
                }
            }
        } finally {
            heldLearningReleaseLock.unlock();
        }
    }

    private static boolean holds(Map<String, HeldRecord> records, HeldEntry entry) {
        HeldRecord record = records.get(entry.requestId());
        return record != null && record.sequence() == entry.sequence();
    }

    /** RPUSH then EXPIRE, keeping the newest {@code maxSize}; a sequence that expired starts anew (Z-16 D-1). */
    private static void appendToStringSequence(
            ExpiringKeySpace<List<String>> target,
            String sequenceKey,
            String value,
            int maxSize) {
        target.compute(sequenceKey, (key, sequence) -> {
            List<String> values = sequence != null ? sequence : Collections.synchronizedList(new ArrayList<>());
            values.add(value);
            while (values.size() > maxSize) {
                values.remove(0);
            }
            return values;
        });
    }

    private void removeExpiredLoginFailures(long nowMs) {
        long staleBefore = (nowMs - loginFailureRetention.toMillis()) * 1_000_000L;
        for (String key : loginFailureCounters.keySet()) {
            loginFailureCounters.computeIfPresent(key, (ignored, counter) ->
                    counter.isEmpty() || counter.lastKey() < staleBefore ? null : counter);
        }
    }

    private void recordLoginFailureCounter(String key, long currentTimeMs) {
        loginFailureCounters.compute(key, (ignored, counter) -> {
            ConcurrentSkipListMap<Long, String> values = counter != null
                    ? counter
                    : new ConcurrentSkipListMap<>();
            long sequence = authenticationEventSequence.incrementAndGet() % 1_000_000L;
            values.put(currentTimeMs * 1_000_000L + sequence, Long.toString(currentTimeMs));
            long cutoff = (currentTimeMs - loginFailureRetention.toMillis()) * 1_000_000L;
            values.headMap(cutoff).clear();
            return values;
        });
    }

    private int countLoginFailures(String key, long windowStartMs, long currentTimeMs) {
        ConcurrentSkipListMap<Long, String> counter = loginFailureCounters.get(key);
        if (counter == null) {
            return 0;
        }
        long from = windowStartMs * 1_000_000L;
        long to = currentTimeMs * 1_000_000L + 999_999L;
        return counter.subMap(from, true, to, true).size();
    }

    private static boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private static List<String> copyOf(List<String> sequence) {
        if (sequence == null) {
            return Collections.emptyList();
        }
        synchronized (sequence) {
            return new ArrayList<>(sequence);
        }
    }

    private List<String> recentStringSequence(List<String> sequence, int count) {
        if (sequence == null || sequence.isEmpty()) {
            return Collections.emptyList();
        }
        synchronized (sequence) {
            int size = sequence.size();
            int fromIndex = Math.max(0, size - count);
            return new ArrayList<>(sequence.subList(fromIndex, size));
        }
    }

    /**
     * QF-42, QF-49: a space keyed by session id keeps at most {@link #MAX_SESSION_ENTRIES} sessions, those whose
     * records expire first going first, and a session goes from all of them together.
     */
    private <V> ExpiringKeySpace<V> sessionScopedSpace(Duration ttl) {
        return ExpiringKeySpace.<V>builder(clock).ttl(ttl).bound(MAX_SESSION_ENTRIES)
                .evictWith(this::evictSession).build();
    }

    /** A user's last request and path, each within the bound, go together. */
    private <V> ExpiringKeySpace<V> userActivitySpace() {
        return ExpiringKeySpace.<V>builder(clock).ttl(USER_ACTIVITY_TTL).bound(MAX_SESSION_ENTRIES)
                .evictWith(this::evictUserActivity).build();
    }

    /** What is learned, each space within the bound on its own. */
    private <V> ExpiringKeySpace<V> learningSpace(Consumer<V> onRemoved) {
        return ExpiringKeySpace.<V>builder(clock).ttl(LEARNING_TTL).bound(MAX_SESSION_ENTRIES)
                .onRemoved(onRemoved).build();
    }

    private void evictSession(String sessionId) {
        sessionScopedSpaces.forEach(space -> space.evict(sessionId));
    }

    private void evictUserActivity(String userId) {
        lastRequestTimes.evict(userId);
        previousPaths.evict(userId);
    }

    private String composeWorkProfileKey(String tenantId, String userId) {
        return composeTenantScopedKey(tenantId, userId);
    }

    private String composeTenantScopedKey(String tenantId, String key) {
        if (tenantId == null || tenantId.isBlank()) {
            return key;
        }
        return tenantId + "::" + key;
    }

    /** How many keys each per-session and per-user space holds, by field name. */
    Map<String, Integer> keyCounts() {
        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("sessionActions", sessionActions.size());
        counts.put("sessionDecisions", sessionDecisions.size());
        counts.put("sessionNarrativeActionFamilies", sessionNarrativeActionFamilies.size());
        counts.put("sessionProtectableAccesses", sessionProtectableAccesses.size());
        counts.put("sessionRequestIntervals", sessionRequestIntervals.size());
        counts.put("sessionStartedAt", sessionStartedAt.size());
        counts.put("sessionLastRequestTimes", sessionLastRequestTimes.size());
        counts.put("sessionPreviousPaths", sessionPreviousPaths.size());
        counts.put("sessionFirstClients", sessionFirstClients.size());
        counts.put("sessionPreviousIds", sessionPreviousIds.size());
        counts.put("sessionRisks", sessionRisks.size());
        counts.put("workProfileObservations", workProfileObservations.size());
        counts.put("roleScopeObservations", roleScopeObservations.size());
        counts.put("permissionChangeObservations", permissionChangeObservations.size());
        counts.put("authorizationScopeStates", authorizationScopeStates.size());
        counts.put("lastRequestTimes", lastRequestTimes.size());
        counts.put("previousPaths", previousPaths.size());
        counts.put("verificationLearning", verificationLearning.size());
        counts.put("promotionLearning", promotionLearning.size());
        counts.put("userSessions", userSessions.size());
        return counts;
    }

    boolean holdsUserRecordsFor(String userId) {
        return mfaVerifiedAt.holds(userId) || userSessions.holds(userId)
                || loginFailureCounters.containsKey("user:" + userId) || stoppedRequests.holds(userId);
    }
}
