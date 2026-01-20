package io.contexa.contexacore.std.components.event;

import io.contexa.contexacommon.enums.SecurityLevel;

import java.time.LocalDateTime;


public class RiskEvent {
    
    private final String eventType;
    private final SecurityLevel riskLevel;
    private final LocalDateTime timestamp;
    private final String description;
    
    public RiskEvent(String eventType, SecurityLevel riskLevel) {
        this(eventType, riskLevel, null);
    }
    
    public RiskEvent(String eventType, SecurityLevel riskLevel, String description) {
        this.eventType = eventType;
        this.riskLevel = riskLevel;
        this.description = description;
        this.timestamp = LocalDateTime.now();
    }
    
    
    
    public String getEventType() {
        return eventType;
    }
    
    public SecurityLevel getRiskLevel() {
        return riskLevel;
    }
    
    public LocalDateTime getTimestamp() {
        return timestamp;
    }
    
    public String getDescription() {
        return description;
    }
    
    @Override
    public String toString() {
        return String.format("RiskEvent{eventType='%s', riskLevel=%s, timestamp=%s, description='%s'}", 
                           eventType, riskLevel, timestamp, description);
    }
} 