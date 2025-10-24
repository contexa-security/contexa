package io.contexa.contexacore.infra.session;

import java.util.Map;

/**
 * AI 연구소 할당 정보
 */
public class AILabAllocation {
    private final String sessionId;
    private final String labType;
    private final String nodeId;
    private final Map<String, Object> allocationData;
    private final long allocationTime;
    
    public AILabAllocation(String sessionId, String labType, String nodeId,
                         Map<String, Object> allocationData, long allocationTime) {
        this.sessionId = sessionId;
        this.labType = labType;
        this.nodeId = nodeId;
        this.allocationData = allocationData;
        this.allocationTime = allocationTime;
    }
    
    // Getters
    public String getSessionId() { return sessionId; }
    public String getLabType() { return labType; }
    public String getNodeId() { return nodeId; }
    public Map<String, Object> getAllocationData() { return allocationData; }
    public long getAllocationTime() { return allocationTime; }
} 