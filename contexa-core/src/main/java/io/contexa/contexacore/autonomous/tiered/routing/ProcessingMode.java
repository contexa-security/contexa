package io.contexa.contexacore.autonomous.tiered.routing;


public enum ProcessingMode {
    
    
    REALTIME_BLOCK,

    
    AI_ANALYSIS,
    
    
    SOAR_ORCHESTRATION,
    
    
    AWAIT_APPROVAL;
    
    
    public boolean isRealtime() {
        return this == REALTIME_BLOCK;
    }
    
    
    public boolean isBlocking() {
        return this == REALTIME_BLOCK;
    }
    
    
    public boolean needsEscalation() {
        return this == SOAR_ORCHESTRATION;
    }
    
    
    public boolean needsMonitoring() {
        return this == AI_ANALYSIS;
    }
    
    
    public boolean needsHumanIntervention() {
        return this == AWAIT_APPROVAL;
    }
    
    
    public static ProcessingMode determineMode(double riskScore, double confidence) {
        
        if (riskScore >= 0.8 && confidence >= 0.8) {
            return REALTIME_BLOCK;
        }

        
        return AI_ANALYSIS;
    }
}