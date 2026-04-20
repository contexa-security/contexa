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
