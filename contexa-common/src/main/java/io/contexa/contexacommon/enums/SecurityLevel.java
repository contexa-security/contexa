package io.contexa.contexacommon.enums;


public enum SecurityLevel {
    
    MINIMAL(1, "최소 보안", "개발 및 테스트 환경에 적합한 기본 보안 수준"),
    
    
    STANDARD(2, "표준 보안", "일반적인 운영 환경에 적합한 표준 보안 수준"),
    
    
    ENHANCED(3, "강화 보안", "중요한 시스템과 데이터를 위한 강화된 보안 수준"),
    
    
    HIGH(4, "높은 보안", "핵심 데이터와 중요 작업을 위한 높은 보안 수준"),
    
    
    MAXIMUM(5, "최고 보안", "핵심 인프라와 극비 데이터를 위한 최고 보안 수준");

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