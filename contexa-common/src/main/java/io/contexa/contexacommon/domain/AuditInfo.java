package io.contexa.contexacommon.domain;

import lombok.Getter;

import java.time.LocalDateTime;


@Getter
public class AuditInfo {
    private final LocalDateTime auditTimestamp;
    private String auditTrailId;
    private String userId;
    private String action;
    private boolean auditRequired;
    
    public AuditInfo() {
        this.auditTimestamp = LocalDateTime.now();
        this.auditRequired = true;
    }
    
    public void recordAction(String userId, String action) {
        this.userId = userId;
        this.action = action;
        this.auditTrailId = generateAuditTrailId();
    }
    
    private String generateAuditTrailId() {
        return "AUDIT_" + System.currentTimeMillis() + "_" + userId;
    }
    
    public void setAuditRequired(boolean auditRequired) { this.auditRequired = auditRequired; }
    
    @Override
    public String toString() {
        return String.format("AuditInfo{id='%s', user='%s', action='%s'}", 
                auditTrailId, userId, action);
    }
} 