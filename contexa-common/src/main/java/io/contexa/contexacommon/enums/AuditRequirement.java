package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum AuditRequirement {
    
    NONE("NONE", "Skip audit logging in dev/test environments"),
    
    
    BASIC("BASIC", "Log only basic actions"),
    
    
    DETAILED("DETAILED", "Log all detailed actions and results"),
    
    
    COMPREHENSIVE("COMPREHENSIVE", "Include all data, tracing info, and performance metrics"),
    
    
    REQUIRED("REQUIRED", "Mandatory audit logging per security requirements");
    
    private final String displayName;
    private final String description;
    
    AuditRequirement(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    
    public boolean isAuditRequired() {
        return this != NONE;
    }
} 