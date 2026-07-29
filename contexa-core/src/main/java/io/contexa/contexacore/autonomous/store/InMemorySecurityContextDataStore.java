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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicLong;

public class InMemorySecurityContextDataStore implements SecurityContextDataStore {

    private static final int MAX_SESSION_ACTIONS = 100;
    private static final int MAX_WORK_PROFILE_OBSERVATIONS = 5_000;
    private static final int MAX_ROLE_SCOPE_OBSERVATIONS = 5_000;
    private static final int MAX_PERMISSION_CHANGE_OBSERVATIONS = 200;
    private static final int MAX_PROCESSED_EVENTS = 50_000;
    private static final int MAX_SOAR_EXECUTIONS = 10_000;
    private static final int MAX_SESSION_ENTRIES = 10_000;

    private static final Duration DEFAULT_EVENT_PROCESSED_TTL = Duration.ofHours(24);
    private static final Duration DEFAULT_SOAR_TTL = Duration.ofDays(7);
    private static final Duration DEFAULT_USER_SESSIONS_TTL = Duration.ofDays(7);
    private static final Duration MFA_VERIFIED_TTL = Duration.ofHours(1);

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
    }

    private final ConcurrentHashMap<String, List<String>> sessionActions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> sessionNarrativeActionFamilies = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> sessionProtectableAccesses = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<Long>> sessionRequestIntervals = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> workProfileObservations = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> roleScopeObservations = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> permissionChangeObservations = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Double> sessionRisks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> sessionStartedAt = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> sessionLastRequestTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> sessionPreviousPaths = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> authorizationScopeStates = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastRequestTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> previousPaths = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ConcurrentSkipListMap<Long, String>> loginFailureCounters =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> mfaVerifiedExpiry = new ConcurrentHashMap<>();
    private final AtomicLong authenticationEventSequence = new AtomicLong();
    private final Object eventProcessingLock = new Object();
    private final Set<String> processingEvents = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Map<String, Instant> processedEventExpiry = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Instant> eldest) {
                    return size() > MAX_PROCESSED_EVENTS;
                }
            });
    private final Map<String, SoarEntry> soarExecutions = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, SoarEntry> eldest) {
                    return size() > MAX_SOAR_EXECUTIONS;
                }
            });
    private final ConcurrentHashMap<String, Set<String>> userSessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> userSessionsExpiry = new ConcurrentHashMap<>();

    private static final class SoarEntry {
        final Object data;
        final Instant expiresAt;

        SoarEntry(Object data, Instant expiresAt) {
            this.data = data;
            this.expiresAt = expiresAt;
        }
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
    public void addSessionNarrativeActionFamily(String sessionId, String actionFamily) {
        appendToStringSequence(sessionNarrativeActionFamilies, sessionId, actionFamily, MAX_SESSION_ACTIONS);
    }

    @Override
    public List<String> getRecentSessionNarrativeActionFamilies(String sessionId, int count) {
        return recentStringSequence(sessionNarrativeActionFamilies.get(sessionId), count);
    }

    @Override
    public void addSessionProtectableAccess(String sessionId, String resourcePath) {
        appendToStringSequence(sessionProtectableAccesses, sessionId, resourcePath, MAX_SESSION_ACTIONS);
    }

    @Override
    public List<String> getRecentSessionProtectableAccesses(String sessionId, int count) {
        return recentStringSequence(sessionProtectableAccesses.get(sessionId), count);
    }

    @Override
    public void addSessionRequestInterval(String sessionId, long intervalMs) {
        sessionRequestIntervals.compute(sessionId, (key, intervals) -> {
            if (intervals == null) {
                intervals = Collections.synchronizedList(new ArrayList<>());
            }
            intervals.add(intervalMs);
            while (intervals.size() > MAX_SESSION_ACTIONS) {
                intervals.remove(0);
            }
            return intervals;
        });
    }

    @Override
    public List<Long> getRecentSessionRequestIntervals(String sessionId, int count) {
        List<Long> intervals = sessionRequestIntervals.get(sessionId);
        if (intervals == null || intervals.isEmpty()) {
            return Collections.emptyList();
        }
        synchronized (intervals) {
            int size = intervals.size();
            int fromIndex = Math.max(0, size - count);
            return new ArrayList<>(intervals.subList(fromIndex, size));
        }
    }

    @Override
    public void setSessionStartedAt(String sessionId, long timestamp) {
        sessionStartedAt.put(sessionId, timestamp);
    }

    @Override
    public Long getSessionStartedAt(String sessionId) {
        return sessionStartedAt.get(sessionId);
    }

    @Override
    public void setSessionLastRequestTime(String sessionId, long timestamp) {
        sessionLastRequestTimes.put(sessionId, timestamp);
    }

    @Override
    public Long getSessionLastRequestTime(String sessionId) {
        return sessionLastRequestTimes.get(sessionId);
    }

    @Override
    public void setSessionPreviousPath(String sessionId, String path) {
        sessionPreviousPaths.put(sessionId, path);
    }

    @Override
    public String getSessionPreviousPath(String sessionId) {
        return sessionPreviousPaths.get(sessionId);
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
                MAX_WORK_PROFILE_OBSERVATIONS);
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
                MAX_ROLE_SCOPE_OBSERVATIONS);
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
        evictIfOversized();
    }

    @Override
    public String getAuthorizationScopeState(String tenantId, String userId) {
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
        Long expiresAt = mfaVerifiedExpiry.get(userId);
        if (expiresAt == null) {
            return false;
        }
        if (clock.millis() >= expiresAt) {
            mfaVerifiedExpiry.remove(userId, expiresAt);
            return false;
        }
        return true;
    }

    @Override
    public void markMfaVerified(String userId) {
        mfaVerifiedExpiry.put(userId, clock.millis() + MFA_VERIFIED_TTL.toMillis());
    }

    @Override
    public EventProcessingClaim claimEventProcessing(String eventId) {
        synchronized (eventProcessingLock) {
            Instant expiresAt = processedEventExpiry.get(eventId);
            if (expiresAt != null) {
                if (clock.instant().isBefore(expiresAt)) {
                    return EventProcessingClaim.PROCESSED;
                }
                processedEventExpiry.remove(eventId);
            }
            if (!processingEvents.add(eventId)) {
                return EventProcessingClaim.IN_FLIGHT;
            }
            return EventProcessingClaim.ACQUIRED;
        }
    }

    @Override
    public void markEventProcessed(String eventId) {
        synchronized (eventProcessingLock) {
            processingEvents.remove(eventId);
            processedEventExpiry.put(eventId, clock.instant().plus(eventProcessedTtl));
        }
    }

    @Override
    public void releaseEventProcessing(String eventId) {
        synchronized (eventProcessingLock) {
            processingEvents.remove(eventId);
        }
    }

    @Override
    public void storeSoarExecution(String eventId, Object data) {
        soarExecutions.put(eventId, new SoarEntry(data, clock.instant().plus(soarTtl)));
    }

    @Override
    public void trackUserSession(String userId, String sessionId) {
        userSessions.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(sessionId);
        userSessionsExpiry.put(userId, clock.instant().plus(userSessionsTtl));
        evictIfOversized();
    }

    Object peekSoarExecution(String eventId) {
        SoarEntry entry = soarExecutions.get(eventId);
        if (entry == null) {
            return null;
        }
        if (clock.instant().isAfter(entry.expiresAt)) {
            soarExecutions.remove(eventId);
            return null;
        }
        return entry.data;
    }

    Set<String> peekUserSessions(String userId) {
        Instant expiresAt = userSessionsExpiry.get(userId);
        if (expiresAt == null) {
            return Collections.emptySet();
        }
        if (clock.instant().isAfter(expiresAt)) {
            userSessionsExpiry.remove(userId);
            userSessions.remove(userId);
            return Collections.emptySet();
        }
        Set<String> sessions = userSessions.get(userId);
        return sessions == null ? Collections.emptySet() : Collections.unmodifiableSet(sessions);
    }

    private void appendToStringSequence(
            ConcurrentHashMap<String, List<String>> target,
            String sequenceKey,
            String value,
            int maxSize) {
        target.compute(sequenceKey, (key, sequence) -> {
            if (sequence == null) {
                sequence = Collections.synchronizedList(new ArrayList<>());
            }
            sequence.add(value);
            while (sequence.size() > maxSize) {
                sequence.remove(0);
            }
            return sequence;
        });
        evictIfOversized();
    }

    private void recordLoginFailureCounter(String key, long currentTimeMs) {
        loginFailureCounters.compute(key, (ignored, counter) -> {
            ConcurrentSkipListMap<Long, String> values = counter != null
                    ? counter
                    : new ConcurrentSkipListMap<>();
            long sequence = authenticationEventSequence.incrementAndGet() % 1_000_000L;
            values.put(currentTimeMs * 1_000_000L + sequence, Long.toString(currentTimeMs));
            long cutoff = (currentTimeMs - Duration.ofMinutes(5).toMillis()) * 1_000_000L;
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

    private void evictIfOversized() {
        if (sessionStartedAt.size() > MAX_SESSION_ENTRIES) {
            sessionStartedAt.keys().asIterator().forEachRemaining(key -> {
                if (sessionStartedAt.size() <= MAX_SESSION_ENTRIES) {
                    return;
                }
                pruneSessionScopedEntries(key);
            });
        }
        if (lastRequestTimes.size() > MAX_SESSION_ENTRIES) {
            lastRequestTimes.keys().asIterator().forEachRemaining(key -> {
                if (lastRequestTimes.size() <= MAX_SESSION_ENTRIES) {
                    return;
                }
                lastRequestTimes.remove(key);
                previousPaths.remove(key);
            });
        }
        if (userSessions.size() > MAX_SESSION_ENTRIES) {
            userSessions.keys().asIterator().forEachRemaining(key -> {
                if (userSessions.size() <= MAX_SESSION_ENTRIES) {
                    return;
                }
                userSessions.remove(key);
            });
        }
        if (workProfileObservations.size() > MAX_SESSION_ENTRIES) {
            workProfileObservations.keys().asIterator().forEachRemaining(key -> {
                if (workProfileObservations.size() <= MAX_SESSION_ENTRIES) {
                    return;
                }
                workProfileObservations.remove(key);
            });
        }
        if (roleScopeObservations.size() > MAX_SESSION_ENTRIES) {
            roleScopeObservations.keys().asIterator().forEachRemaining(key -> {
                if (roleScopeObservations.size() <= MAX_SESSION_ENTRIES) {
                    return;
                }
                roleScopeObservations.remove(key);
            });
        }
        if (permissionChangeObservations.size() > MAX_SESSION_ENTRIES) {
            permissionChangeObservations.keys().asIterator().forEachRemaining(key -> {
                if (permissionChangeObservations.size() <= MAX_SESSION_ENTRIES) {
                    return;
                }
                permissionChangeObservations.remove(key);
            });
        }
        if (authorizationScopeStates.size() > MAX_SESSION_ENTRIES) {
            authorizationScopeStates.keys().asIterator().forEachRemaining(key -> {
                if (authorizationScopeStates.size() <= MAX_SESSION_ENTRIES) {
                    return;
                }
                authorizationScopeStates.remove(key);
            });
        }
    }

    private void pruneSessionScopedEntries(String sessionId) {
        sessionActions.remove(sessionId);
        sessionNarrativeActionFamilies.remove(sessionId);
        sessionProtectableAccesses.remove(sessionId);
        sessionRequestIntervals.remove(sessionId);
        sessionRisks.remove(sessionId);
        sessionStartedAt.remove(sessionId);
        sessionLastRequestTimes.remove(sessionId);
        sessionPreviousPaths.remove(sessionId);
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
}
