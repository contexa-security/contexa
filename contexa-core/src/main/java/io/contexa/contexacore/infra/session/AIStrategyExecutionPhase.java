package io.contexa.contexacore.infra.session;

/**
 * AI 전략 실행 단계
 */
public enum AIStrategyExecutionPhase {
    INITIALIZED("초기화됨"),
    PLANNING("계획 수립 중"),
    LAB_ALLOCATION("연구소 할당 중"),
    EXECUTING("실행 중"),
    VALIDATING("검증 중"),
    COMPLETED("완료됨"),
    FAILED("실패함"),
    CANCELLED("취소됨");
    
    private final String description;
    
    AIStrategyExecutionPhase(String description) {
        this.description = description;
    }
    
    public String getDescription() { return description; }
} 