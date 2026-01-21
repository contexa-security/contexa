package io.contexa.contexacommon.enums;


public enum SecurityLevel {
    
    MINIMAL(1, "Minimal Security", "Basic security level suitable for dev/test environments"),
    
    
    STANDARD(2, "Standard Security", "Standard security level suitable for general operational environments"),
    
    
    ENHANCED(3, "Enhanced Security", "Enhanced security level for critical systems and data"),
    
    
    HIGH(4, "High Security", "High security level for core data and critical operations"),
    
    
    MAXIMUM(5, "Maximum Security", "Maximum security level for core infrastructure and top-secret data");

    private final int level;
    private final String displayName;
    private final String description;
    
    SecurityLevel(int level, String displayName, String description) {
        this.level = level;
        this.displayName = displayName;
        this.description = description;
    }
    
    
    public int getLevel() {
        return level;
    }
    
    
    public String getDisplayName() {
        return displayName;
    }
    
    
    public String getDescription() {
        return description;
    }
    
    
    public boolean meetsRequirement(SecurityLevel requiredLevel) {
        return this.level >= requiredLevel.level;
    }
} 