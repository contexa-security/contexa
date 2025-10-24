package io.contexa.contexacommon.enums;

import lombok.Getter;

/**
 * 실행 상태
 * SRP 준수: 실행 상태 정의만 담당
 */
@Getter
public enum ExecutionStatus {
    PENDING("대기중", "요청이 대기 중입니다"),
    PROCESSING("처리중", "요청을 처리하고 있습니다"),
    SUCCESS("성공", "요청이 성공적으로 완료되었습니다"),
    PARTIAL_SUCCESS("부분성공", "요청이 부분적으로 성공했습니다"),
    COMPLETED("완료", "요청이 완료되었습니다"),
    FAILED("실패", "요청 처리에 실패했습니다"),
    TIMEOUT("시간초과", "요청 처리 시간이 초과되었습니다"),
    CANCELLED("취소됨", "요청이 취소되었습니다");
    
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