package io.contexa.contexacore.infra.session;

import java.time.Duration;
import java.util.Map;

/**
 * AI 전략 세션 상태
 */
public class AIStrategySessionState {
    private final String sessionId;
    private final String strategyId;
    private final AIStrategyExecutionPhase phase;
    private final String nodeId;
    private final long createTime;
    private final long lastUpdateTime;
    private final Map<String, Object> context;
    private final Map<String, Object> phaseData;
    
    public AIStrategySessionState(String sessionId, String strategyId, 
                                AIStrategyExecutionPhase phase, String nodeId,
                                long createTime, long lastUpdateTime,
                                Map<String, Object> context, 
                                Map<String, Object> phaseData) {
        this.sessionId = sessionId;
        this.strategyId = strategyId;
        this.phase = phase;
        this.nodeId = nodeId;
        this.createTime = createTime;
        this.lastUpdateTime = lastUpdateTime;
        this.context = context;
        this.phaseData = phaseData;
    }
    
    // Getters
    public String getSessionId() { return sessionId; }
    public String getStrategyId() { return strategyId; }
    public AIStrategyExecutionPhase getPhase() { return phase; }
    public String getNodeId() { return nodeId; }
    public long getCreateTime() { return createTime; }
    public long getLastUpdateTime() { return lastUpdateTime; }
    public Map<String, Object> getContext() { return context; }
    public Map<String, Object> getPhaseData() { return phaseData; }
    
    public boolean isActive() {
        return phase != AIStrategyExecutionPhase.COMPLETED && 
               phase != AIStrategyExecutionPhase.FAILED && 
               phase != AIStrategyExecutionPhase.CANCELLED;
    }
    
    public Duration getExecutionDuration() {
        return Duration.ofMillis(lastUpdateTime - createTime);
    }
} 