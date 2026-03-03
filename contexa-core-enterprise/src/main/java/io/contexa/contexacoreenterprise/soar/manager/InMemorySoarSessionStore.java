package io.contexa.contexacoreenterprise.soar.manager;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemorySoarSessionStore implements SoarSessionStore {

    private final Map<String, SoarInteractionManager.InteractionSession> sessions = new ConcurrentHashMap<>();

    @Override
    public Optional<SoarInteractionManager.InteractionSession> getSession(String sessionId) {
        return Optional.ofNullable(sessions.get(sessionId));
    }

    @Override
    public void saveSession(SoarInteractionManager.InteractionSession session) {
        sessions.put(session.getSessionId(), session);
    }

    @Override
    public void removeSession(String sessionId) {
        sessions.remove(sessionId);
    }
}
