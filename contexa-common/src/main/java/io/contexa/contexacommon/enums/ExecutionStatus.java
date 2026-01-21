package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum ExecutionStatus {
    PENDING("Pending", "Request is pending"),
    PROCESSING("Processing", "Request is being processed"),
    SUCCESS("Success", "Request completed successfully"),
    PARTIAL_SUCCESS("Partial Success", "Request partially succeeded"),
    COMPLETED("Completed", "Request completed"),
    FAILED("Failed", "Request processing failed"),
    TIMEOUT("Timeout", "Request processing timed out"),
    CANCELLED("Cancelled", "Request was cancelled");
    
    private final String displayName;
    private final String description;
    
    ExecutionStatus(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    
    public boolean isCompleted() {
        return this == SUCCESS || this == COMPLETED || this == PARTIAL_SUCCESS || this == FAILED || this == TIMEOUT || this == CANCELLED;
    }
    
    public boolean isSuccessful() {
        return this == SUCCESS || this == PARTIAL_SUCCESS;
    }
} 