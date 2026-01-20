package io.contexa.contexacore.autonomous.event;

import java.time.LocalDateTime;
import java.util.Map;


public interface LearnableEvent {
    
    
    enum EventType {
        
        DYNAMIC_THREAT_RESPONSE,
        
        
        STATIC_ACCESS_ANALYSIS,
        
        
        PERFORMANCE_ANOMALY,
        
        
        COMPLIANCE_VIOLATION,
        
        
        USER_BEHAVIOR_ANOMALY
    }
    
    
    String getEventId();
    
    
    EventType getEventType();
    
    
    LocalDateTime getOccurredAt();
    
    
    String getSource();
    
    
    String getSeverity();
    
    
    String getDescription();
    
    
    Map<String, Object> getContext();
    
    
    boolean isResponseSuccessful();
    
    
    String getResponseDescription();
    
    
    default int getLearningPriority() {
        switch (getSeverity()) {
            case "CRITICAL":
                return 100;
            case "HIGH":
                return 75;
            case "MEDIUM":
                return 50;
            case "LOW":
                return 25;
            default:
                return 10;
        }
    }
    
    
    default boolean requiresPolicyGeneration() {
        return isResponseSuccessful() && 
               (getEventType() == EventType.DYNAMIC_THREAT_RESPONSE || 
                getEventType() == EventType.STATIC_ACCESS_ANALYSIS);
    }
}