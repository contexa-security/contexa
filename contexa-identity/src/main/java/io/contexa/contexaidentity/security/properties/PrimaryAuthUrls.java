package io.contexa.contexaidentity.security.properties;

import lombok.Data;

/**
 * 1차 인증 URL 설정
 */
@Data
public class PrimaryAuthUrls {
    /**
     * Form 로그인 처리 URL (POST)
     */
    private String formLoginProcessing = "/login";

    /**
     * Form 로그인 페이지 URL (GET)
     */
    private String formLoginPage = "/loginForm";

    /**
     * REST API 로그인 처리 URL (POST)
     */
    private String restLoginProcessing = "/api/auth/login";

    /**
     * 로그인 실패 리다이렉트 URL
     */
    private String loginFailure = "/login?error";

    /**
     * 로그인 성공 리다이렉트 URL
     */
    private String loginSuccess = "/home";

    /**
     * 로그아웃 페이지 URL
     */
    private String logoutPage = "/logout";
}
