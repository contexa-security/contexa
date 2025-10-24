package io.contexa.contexacore.infra.session;

import java.util.Map;

/**
 * AI 전략 세션 통계
 */
public class AIStrategySessionStats extends SessionStats {
    private final long activeStrategySessions;
    private final long completedStrategySessions;
    private final long failedStrategySessions;
    private final double averageExecutionTime;
    private final Map<String, Long> labTypeDistribution;
    private final Map<String, Long> nodeDistribution;
    
    public AIStrategySessionStats(long activeSessions, long totalSessionsCreated,
                                long sessionCollisions, double averageSessionDuration,
                                String repositoryType, long activeStrategySessions,
                                long completedStrategySessions, long failedStrategySessions,
                                double averageExecutionTime, Map<String, Long> labTypeDistribution,
                                Map<String, Long> nodeDistribution) {
        super(activeSessions, totalSessionsCreated, sessionCollisions, 
              averageSessionDuration, repositoryType);
        this.activeStrategySessions = activeStrategySessions;
        this.completedStrategySessions = completedStrategySessions;
        this.failedStrategySessions = failedStrategySessions;
        this.averageExecutionTime = averageExecutionTime;
        this.labTypeDistribution = labTypeDistribution;
        this.nodeDistribution = nodeDistribution;
    }
    
    // Getters
    public long getActiveStrategySessions() { return activeStrategySessions; }
    public long getCompletedStrategySessions() { return completedStrategySessions; }
    public long getFailedStrategySessions() { return failedStrategySessions; }
    public double getAverageExecutionTime() { return averageExecutionTime; }
    public Map<String, Long> getLabTypeDistribution() { return labTypeDistribution; }
    public Map<String, Long> getNodeDistribution() { return nodeDistribution; }
    
    public double getStrategySuccessRate() {
        long total = completedStrategySessions + failedStrategySessions;
        return total > 0 ? (double) completedStrategySessions / total : 0.0;
    }
}
