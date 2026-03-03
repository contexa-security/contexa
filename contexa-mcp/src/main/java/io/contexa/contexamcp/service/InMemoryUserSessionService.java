package io.contexa.contexamcp.service;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class InMemoryUserSessionService implements UserSessionService {

    private final Map<String, SessionInfo> sessions = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> userSessions = new ConcurrentHashMap<>();

    @Override
    public List<SessionInfo> findActiveSessionsByUserId(String userId) {
        Set<String> sessionIds = userSessions.get(userId);
        if (sessionIds == null || sessionIds.isEmpty()) {
            return Collections.emptyList();
        }

        return sessionIds.stream()
                .map(sessions::get)
                .filter(s -> s != null && s.isActive())
                .collect(Collectors.toList());
    }

    @Override
    public boolean terminateSession(String sessionId) {
        SessionInfo session = sessions.get(sessionId);
        if (session == null) {
            return false;
        }

        session.setActive(false);
        session.setTerminatedAt(Instant.now());

        Set<String> userSessionSet = userSessions.get(session.getUserId());
        if (userSessionSet != null) {
            userSessionSet.remove(sessionId);
        }

        return true;
    }
}
