package io.contexa.contexacore.infra.session;

/**
 * 세션 통계 정보 클래스
 */
public class SessionStats {
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

    // Getters
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
