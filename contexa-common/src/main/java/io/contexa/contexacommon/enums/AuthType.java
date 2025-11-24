package io.contexa.contexacommon.enums;

/**
 * 인증 팩터 타입
 * 각 팩터마다 챌린지 재사용 정책을 정의합니다.
 */
public enum AuthType {
    FORM(false),
    REST(false),

    // MFA 팩터들
    PASSKEY(false),      // Passkey: UI 페이지 표시는 리소스 소비 없음, 매번 상태 전이 필요
    OTT(true),           // OTT: 이메일 발송 비용 있음, 중복 발송 방지 필요
    RECOVERY_CODE(true), // Recovery Code: 코드 생성 비용 있음, 재사용 가능

    // 플로우 타입
    MFA(false),
    MFA_FORM(false),
    MFA_REST(false),
    MFA_OTT(false),
    MFA_PASSKEY(false),
    PRIMARY(false);

    /**
     * 챌린지 재사용 허용 여부
     * - true: 챌린지 생성 비용이 있어 재사용 필요 (예: OTT 이메일 발송)
     * - false: 챌린지 생성 비용 없음, 매번 새로 생성 (예: Passkey UI 표시)
     */
    private final boolean allowChallengeReuse;

    AuthType(boolean allowChallengeReuse) {
        this.allowChallengeReuse = allowChallengeReuse;
    }

    /**
     * 챌린지 재사용 허용 여부 반환
     * @return true: 챌린지 재사용 허용, false: 매번 새로 생성
     */
    public boolean isAllowChallengeReuse() {
        return allowChallengeReuse;
    }
}
