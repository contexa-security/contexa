package io.contexa.contexacoreenterprise.soar.manager;

import java.util.Optional;

public interface SoarSessionStore {

    Optional<SoarInteractionManager.InteractionSession> getSession(String sessionId);

    void saveSession(SoarInteractionManager.InteractionSession session);

    void removeSession(String sessionId);
}
