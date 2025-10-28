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
     */
    private String success = "/home";

    /**
     * MFA 실패 페이지 URL
     */
    private String failure = "/mfa/failure";

    /**
     * MFA 취소 리다이렉트 URL
     */
    private String cancel = "/loginForm";

    /**
     * MFA 상태 조회 URL (deprecated - use ApiUrls.status)
     */
    private String status = "/mfa/status";
}
