package io.contexa.contexaidentity.security.properties;

import lombok.Data;

/**
 * MFA 라이프사이클 URL 설정
 */
@Data
public class MfaUrls {
    /**
     * MFA 프로세스 시작 URL
     */
    private String initiate = "/mfa/initiate";

    /**
     * MFA 설정 UI URL
     */
    private String configure = "/mfa/configure";

    /**
     * Factor 선택 UI 페이지 URL (GET)
     */
    private String selectFactorUi = "/mfa/select-factor";

    /**
     * MFA 성공 리다이렉트 URL
     *
     * <p>
     * 주의: Primary Auth의 loginSuccess와 동일한 URL을 사용하면 중복 검증 실패합니다.
     * 하지만 기능적으로 동일한 목적지이므로, 실제로는 Primary loginSuccess URL을 참조해야 합니다.
     * 검증 로직에서 이 경우는 허용되어야 합니다.
     * </p>
     */
    private String success = "/home";

    /**
     * MFA 실패 페이지 URL
     */
    private String failure = "/mfa/failure";

    /**
     * MFA 취소 리다이렉트 URL
     *
     * <p>
     * 주의: Primary Auth의 formLoginPage와 동일한 URL을 사용하면 중복 검증 실패합니다.
     * MFA 취소 시 로그인 페이지로 돌아가는 것이 자연스러우므로, 이 중복은 의도된 것입니다.
     * 검증 로직에서 이 경우는 허용되어야 합니다.
     * </p>
     */
    private String cancel = "/loginForm";

    /**
     * MFA 상태 조회 URL (deprecated - use ApiUrls.status)
     */
    private String status = "/mfa/status";
}
