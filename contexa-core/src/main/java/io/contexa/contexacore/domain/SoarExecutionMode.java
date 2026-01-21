package io.contexa.contexacore.domain;

public enum SoarExecutionMode {

    SYNC("sync", "Synchronous approval processing with blocking wait"),

    ASYNC("async", "Asynchronous approval processing with persistence"),

    AUTO("auto", "Automatic mode selection based on context");
    
    private final String code;
    private final String description;
    
    SoarExecutionMode(String code, String description) {
        this.code = code;
        this.description = description;
    }
    
    public String getCode() {
        return code;
    }
    
    public String getDescription() {
        return description;
    }

    public static SoarExecutionMode fromCode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return AUTO;
        }
        
        for (SoarExecutionMode mode : values()) {
            if (mode.code.equalsIgnoreCase(code.trim())) {
                return mode;
            }
        }
        
        return AUTO;
    }

    public boolean isSync() {
        return this == SYNC;
    }

    public boolean isAsync() {
        return this == ASYNC;
    }

    public boolean isAuto() {
        return this == AUTO;
    }
}