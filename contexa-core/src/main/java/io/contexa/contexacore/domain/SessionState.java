package io.contexa.contexacore.domain;

/**
 * SOAR 세션 상태
 */
public enum SessionState {
    NEW("신규"),  // Jackson 역직렬화 오류 해결을 위해 추가
    INITIALIZED("초기화됨"),
    ACTIVE("활성"),
    ANALYZING("분석 중"),
    INVESTIGATING("조사 중"),  // Jackson 역직렬화 오류 해결을 위해 추가
    WAITING_APPROVAL("승인 대기 중"),
    AWAITING_APPROVAL("승인 대기 중"),  // 호환성을 위해 추가
    CONFIRMED("확인됨"),
    APPROVED("승인됨"),
    EXECUTING("실행 중"),
    COMPLETED("완료"),
    FAILED("실패"),
    ERROR("오류");
    
    private final String description;
    
    SessionState(String description) {
        this.description = description;
    }
    
    public String getDescription() {
        return description;
    }
}