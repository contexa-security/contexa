package io.contexa.contexaidentity.security.statemachine.enums;

import lombok.Getter;

@Getter
public enum MfaState {

    
    NONE("MFA 세션 없음"),

    
    PRIMARY_AUTHENTICATION_COMPLETED("1차 인증 완료"),

    
    MFA_NOT_REQUIRED("MFA 불필요"),

    
    AWAITING_FACTOR_SELECTION("2차 인증 수단 선택 대기"),
    AWAITING_FACTOR_CHALLENGE_INITIATION("2차 인증 챌린지 시작 대기"),
    FACTOR_CHALLENGE_INITIATED("챌린지 발송/생성 완료"),
    FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION("사용자 입력 대기"),
    FACTOR_VERIFICATION_PENDING("팩터 검증 진행 중"),
    FACTOR_VERIFICATION_IN_PROGRESS("팩터 검증 처리 중"), 
    FACTOR_VERIFICATION_COMPLETED("팩터 검증 완료"),

    
    ALL_FACTORS_COMPLETED("모든 필수 팩터 완료"),
    MFA_SUCCESSFUL("MFA 최종 성공"),
    MFA_FAILED_TERMINAL("MFA 최종 실패"),
    MFA_CANCELLED("사용자 취소"),
    MFA_SESSION_EXPIRED("세션 만료"),
    MFA_SESSION_INVALIDATED("세션 무효화"),
    MFA_RETRY_LIMIT_EXCEEDED("재시도 횟수 초과"),
    MFA_SYSTEM_ERROR("시스템 오류");

    private final String description;

    MfaState(String description) {
        this.description = description;
    }

    public boolean isTerminal() {
        return this == MFA_SUCCESSFUL ||
                this == MFA_NOT_REQUIRED ||
                this == MFA_FAILED_TERMINAL ||
                this == MFA_CANCELLED ||
                this == MFA_SESSION_EXPIRED ||
                this == MFA_SESSION_INVALIDATED ||
                this == MFA_RETRY_LIMIT_EXCEEDED ||
                this == MFA_SYSTEM_ERROR;
    }

    public boolean isWaitingForUserAction() {
        return this == AWAITING_FACTOR_SELECTION ||
                this == FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
    }

    public boolean isProcessing() {
        return this == AWAITING_FACTOR_CHALLENGE_INITIATION ||
                this == FACTOR_CHALLENGE_INITIATED ||
                this == FACTOR_VERIFICATION_PENDING;
    }
}