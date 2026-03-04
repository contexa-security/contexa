package io.contexa.contexacore.domain;

public enum SessionState {
    NEW("New"),
    INITIALIZED("Initialized"),
    ACTIVE("Active"),
    ANALYZING("Analyzing"),
    INVESTIGATING("Investigating"),
    WAITING_APPROVAL("Waiting Approval"),
    AWAITING_APPROVAL("Awaiting Approval"),
    CONFIRMED("Confirmed"),
    APPROVED("Approved"),
    EXECUTING("Executing"),
    COMPLETED("Completed"),
    FAILED("Failed"),
    ERROR("Error");
    
    private final String description;
    
    SessionState(String description) {
        this.description = description;
    }
    
    public String getDescription() {
        return description;
    }
}