package io.contexa.contexacommon.enums;

/**
 * IAM 작업의 보안 수준을 정의하는 열거형
 * AI 작업시 적용될 보안 정책의 강도를 결정합니다
 */
public enum SecurityLevel {
    /**
     * 최소 보안 - 개발/테스트 환경
     */
    MINIMAL(1, "최소 보안", "개발 및 테스트 환경에 적합한 기본 보안 수준"),
    
    /**
     * 표준 보안 - 일반 운영 환경
     */
    STANDARD(2, "표준 보안", "일반적인 운영 환경에 적합한 표준 보안 수준"),
    
    /**
     * 강화 보안 - 중요 시스템
     */
    ENHANCED(3, "강화 보안", "중요한 시스템과 데이터를 위한 강화된 보안 수준"),
    
    /**
     * 높은 보안 - 핵심 데이터
     */
    HIGH(4, "높은 보안", "핵심 데이터와 중요 작업을 위한 높은 보안 수준"),
    
    /**
     * 최고 보안 - 핵심 인프라
     */
    MAXIMUM(5, "최고 보안", "핵심 인프라와 극비 데이터를 위한 최고 보안 수준");

    private final int level;
    private final String displayName;
    private final String description;
    
    SecurityLevel(int level, String displayName, String description) {
        this.level = level;
        this.displayName = displayName;
        this.description = description;
    }
    
    /**
     * 보안 수준의 숫자 값을 반환합니다
     * @return 보안 수준 (1-5)
     */
    public int getLevel() {
        return level;
    }
    
    /**
     * 보안 수준의 표시명을 반환합니다
     * @return 한국어 표시명
     */
    public String getDisplayName() {
        return displayName;
    }
    
    /**
     * 보안 수준의 상세 설명을 반환합니다
     * @return 상세 설명
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * 현재 보안 수준이 지정된 수준보다 높거나 같은지 확인합니다
     * @param requiredLevel 필요한 최소 보안 수준
     * @return 보안 수준 충족 여부
     */
    public boolean meetsRequirement(SecurityLevel requiredLevel) {
        return this.level >= requiredLevel.level;
    }
} 