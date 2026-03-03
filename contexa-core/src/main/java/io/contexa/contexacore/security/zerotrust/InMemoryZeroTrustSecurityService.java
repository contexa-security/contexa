package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryZeroTrustSecurityService extends AbstractZeroTrustSecurityService {

    private final Set<String> invalidatedSessions = ConcurrentHashMap.newKeySet();
    private final Map<String, Set<String>> userSessions = new ConcurrentHashMap<>();

    public InMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster) {
        super(threatScoreUtil, securityZeroTrustProperties, actionRepository);
        this.blockingSignalBroadcaster = blockingSignalBroadcaster;
    }

    @Override
    public void invalidateSession(String sessionId, String userId, String reason) {
        if (sessionId == null) {
            return;
        }
        invalidatedSessions.add(sessionId);
    }

    @Override
    public boolean isSessionInvalidated(String sessionId) {
        if (sessionId == null) {
            return false;
        }
        return invalidatedSessions.contains(sessionId);
    }

    @Override
    protected void doRegisterSession(String userId, String sessionId) {
        userSessions.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(sessionId);
    }

    @Override
    protected void doCleanupSessionData(String userId, String sessionId) {
        if (sessionId != null) {
            invalidatedSessions.remove(sessionId);
            Set<String> sessions = userSessions.get(userId);
            if (sessions != null) {
                sessions.remove(sessionId);
            }
        }
    }

    @Override
    public void invalidateAllUserSessions(String userId, String reason) {
        if (userId == null) {
            return;
        }

        Set<String> sessions = userSessions.remove(userId);
        if (sessions != null) {
            for (String sessionId : sessions) {
                invalidateSession(sessionId, userId, reason);
            }
        }
    }
}
