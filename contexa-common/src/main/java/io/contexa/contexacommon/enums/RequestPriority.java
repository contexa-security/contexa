package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum RequestPriority {
    LOW("Low", 1),
    NORMAL("Normal", 2),
    HIGH("High", 3),
    URGENT("Urgent", 4),
    CRITICAL("Critical", 5);
    
    private final String displayName;
    private final int level;
    
    RequestPriority(String displayName, int level) {
        this.displayName = displayName;
        this.level = level;
    }
    
    public boolean isHigherThan(RequestPriority other) {
        return this.level > other.level;
    }
} 