package io.contexa.contexaidentity.security.properties;

import lombok.Data;

/**
 * MFA 1차 인증 URL 설정
 */
@Data
public class PrimaryAuthUrls {
    /**
     * Form 로그인 처리 URL (POST)
     * MFA 기본값: /mfa/login
     */
    private String formLoginProcessing = "/mfa/login";

    /**
     * Form 로그인 페이지 URL (GET)
     * MFA 기본값: /mfa/login
     */
    private String formLoginPage = "/mfa/login";

    /**
     * REST API 로그인 처리 URL (POST)
     * MFA 기본값: /api/mfa/login
     */
    private String restLoginProcessing = "/api/mfa/login";

    /**
     * 로그인 실패 리다이렉트 URL
     */
    private String loginFailure = "/login?error";

    /**
     * 로그인 성공 리다이렉트 URL
     */
    private String loginSuccess = "/";

    /**
     * 로그아웃 페이지 URL
     */
    private String logoutPage = "/logout";
}
