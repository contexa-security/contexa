package io.contexa.contexacore.infra.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;

import java.time.Duration;


public interface MfaSessionRepository {

    

    void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    @Nullable
    String getSessionId(HttpServletRequest request);

    void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    void refreshSession(String sessionId);

    boolean existsSession(String sessionId);

    void setSessionTimeout(Duration timeout);

    String getRepositoryType();

    

    
    String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request);

    
    boolean isSessionIdUnique(String sessionId);

    
    String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts);

    
    boolean isValidSessionIdFormat(String sessionId);

    
    boolean supportsDistributedSync();

    
    SessionStats getSessionStats();

    class SessionStats {
        private final long activeSessions;
        private final long totalSessionsCreated;
        private final long sessionCollisions;
        private final double averageSessionDuration;
        private final String repositoryType;

        public SessionStats(long activeSessions, long totalSessionsCreated,
                            long sessionCollisions, double averageSessionDuration,
                            String repositoryType) {
            this.activeSessions = activeSessions;
            this.totalSessionsCreated = totalSessionsCreated;
            this.sessionCollisions = sessionCollisions;
            this.averageSessionDuration = averageSessionDuration;
            this.repositoryType = repositoryType;
        }

        
        public long getActiveSessions() { return activeSessions; }
        public long getTotalSessionsCreated() { return totalSessionsCreated; }
        public long getSessionCollisions() { return sessionCollisions; }
        public double getAverageSessionDuration() { return averageSessionDuration; }
        public String getRepositoryType() { return repositoryType; }

        @Override
        public String toString() {
            return String.format("SessionStats{type=%s, active=%d, total=%d, collisions=%d, avgDuration=%.2fs}",
                    repositoryType, activeSessions, totalSessionsCreated, sessionCollisions, averageSessionDuration);
        }
    }
}