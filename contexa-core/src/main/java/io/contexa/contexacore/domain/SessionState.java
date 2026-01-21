package io.contexa.contexacore.domain;

public enum SessionState {
    NEW("신규"),  
    INITIALIZED("초기화됨"),
    ACTIVE("활성"),
    ANALYZING("분석 중"),
    INVESTIGATING("조사 중"),  
    WAITING_APPROVAL("승인 대기 중"),
    AWAITING_APPROVAL("승인 대기 중"),  
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