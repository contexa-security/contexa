package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum RequestPriority {
    LOW("낮음", 1),
    NORMAL("보통", 2),
    HIGH("높음", 3),
    URGENT("긴급", 4),
    CRITICAL("매우긴급", 5);
    
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