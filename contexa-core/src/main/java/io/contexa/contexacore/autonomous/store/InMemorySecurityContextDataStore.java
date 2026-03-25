package io.contexa.contexacore.autonomous.store;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class InMemorySecurityContextDataStore implements SecurityContextDataStore {

    private static final int MAX_SESSION_ACTIONS = 100;
    private static final int MAX_WORK_PROFILE_OBSERVATIONS = 5_000;
    private static final int MAX_PROCESSED_EVENTS = 50_000;
    private static final int MAX_SOAR_EXECUTIONS = 10_000;
    private static final int MAX_SESSION_ENTRIES = 10_000;

    private final ConcurrentHashMap<String, List<String>> sessionActions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> sessionNarrativeActionFamilies = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> sessionProtectableAccesses = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<Long>> sessionRequestIntervals = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> workProfileObservations = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Double> sessionRisks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> sessionStartedAt = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> sessionLastRequestTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> sessionPreviousPaths = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastRequestTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> previousPaths = new ConcurrentHashMap<>();
    private final Set<String> processedEvents = Collections.newSetFromMap(
            Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                    return size() > MAX_PROCESSED_EVENTS;
                }
            }));
    private final Map<String, Object> soarExecutions = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Object> eldest) {
                    return size() > MAX_SOAR_EXECUTIONS;
                }
            });
    private final ConcurrentHashMap<String, Set<String>> userSessions = new ConcurrentHashMap<>();

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
    public boolean tryMarkEventAsProcessed(String eventId) {
        return processedEvents.add(eventId);
    }

    @Override
    public void storeSoarExecution(String eventId, Object data) {
        soarExecutions.put(eventId, data);
    }

    @Override
    public void trackUserSession(String userId, String sessionId) {
        userSessions.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(sessionId);
        evictIfOversized();
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
        if (tenantId == null || tenantId.isBlank()) {
            return userId;
        }
        return tenantId + "::" + userId;
    }
}
