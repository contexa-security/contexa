package io.contexa.contexaiam.domain.entity.enums;


public enum Status {
    ACTIVE("활성"),
    INACTIVE("비활성"),
    PENDING("대기중"),
    DELETED("삭제됨");
    
    private final String displayName;
    
    Status(String displayName) {
        this.displayName = displayName;
    }
    
    public String getDisplayName() { return displayName; }
}