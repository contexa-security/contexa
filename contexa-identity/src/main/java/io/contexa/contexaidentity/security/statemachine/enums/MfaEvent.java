package io.contexa.contexaidentity.security.statemachine.enums;

public enum MfaEvent {

    // --- 1차 인증 ---
    PRIMARY_AUTH_SUCCESS,              // 1차 인증 성공
    PRIMARY_AUTH_FAILURE,              // 1차 인증 실패

    // --- MFA 정책 평가 결과 ---
    MFA_NOT_REQUIRED,                  // MFA 불필요
    MFA_REQUIRED_SELECT_FACTOR,        // MFA 필요, 사용자 선택
    MFA_CONFIGURATION_REQUIRED,        // MFA 설정 필요

    // --- 팩터 선택 및 챌린지 ---
    FACTOR_SELECTED,                   // 사용자가 팩터 선택
    INITIATE_CHALLENGE,                // 챌린지 시작 요청
    INITIATE_CHALLENGE_AUTO,           // 자동 선택 후 챌린지 시작
    CHALLENGE_INITIATED_SUCCESSFULLY,  // 챌린지 성공적 시작
    CHALLENGE_INITIATION_FAILED,       // 챌린지 시작 실패

    // --- 팩터 검증 ---
    SUBMIT_FACTOR_CREDENTIAL,          // 사용자가 인증 정보 제출
    FACTOR_VERIFIED_SUCCESS,           // 팩터 검증 성공
    FACTOR_VERIFICATION_FAILED,        // 팩터 검증 실패

    // --- MFA 완료 ---
    ALL_REQUIRED_FACTORS_COMPLETED,    // 모든 필수 팩터 완료
    ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN, // 최종 토큰 발급 진행

    // --- 예외 상황 ---
    USER_ABORTED_MFA,                  // 사용자 취소
    RETRY_LIMIT_EXCEEDED,              // 재시도 한계 초과
    SESSION_TIMEOUT,                   // 세션 타임아웃
    CHALLENGE_TIMEOUT,                 // 챌린지 타임아웃
    SYSTEM_ERROR,                      // 시스템 오류
    
    // --- AI 적응형 인증 이벤트 ---
    AUTHENTICATION_BLOCKED,            // AI가 인증 차단 결정
    RISK_LEVEL_ELEVATED,              // 위험도 상승 감지
    ADAPTIVE_MFA_REQUIRED,            // 적응형 MFA 요구
    AI_ASSESSMENT_COMPLETED           // AI 평가 완료
}