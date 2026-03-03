package io.contexa.contexacore.autonomous.store;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class InMemorySecurityContextDataStore implements SecurityContextDataStore {

    private static final int MAX_SESSION_ACTIONS = 100;

    private final ConcurrentHashMap<String, List<String>> sessionActions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Double> sessionRisks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastRequestTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> previousPaths = new ConcurrentHashMap<>();
    private final Set<String> processedEvents = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Object> soarExecutions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> userSessions = new ConcurrentHashMap<>();

    @Override
    public void addSessionAction(String sessionId, String action) {
        sessionActions.compute(sessionId, (key, actions) -> {
            if (actions == null) {
                actions = Collections.synchronizedList(new ArrayList<>());
            }
            actions.add(action);
            while (actions.size() > MAX_SESSION_ACTIONS) {
                actions.removeFirst();
            }
            return actions;
        });
    }

    @Override
    public List<String> getRecentSessionActions(String sessionId, int count) {
        List<String> actions = sessionActions.get(sessionId);
        if (actions == null || actions.isEmpty()) {
            return Collections.emptyList();
        }
        synchronized (actions) {
            int size = actions.size();
            int fromIndex = Math.max(0, size - count);
            return new ArrayList<>(actions.subList(fromIndex, size));
        }
    }

    @Override
    public void setSessionRisk(String sessionId, double riskScore) {
        sessionRisks.put(sessionId, riskScore);
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
    }
}
