package io.contexa.contexaidentity.security.properties;

import lombok.Data;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * 단일 인증 URL 설정 (MFA 없는 독립 인증)
 */
@Data
public class SingleAuthUrls {
    /**
     * Form 로그인 처리 URL (POST)
     * Spring Security 기본값: /login
     */
    private String formLoginProcessing = "/login";

    /**
     * Form 로그인 페이지 URL (GET)
     * Spring Security 기본값: /login
     */
    private String formLoginPage = "/login";

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
    private String loginSuccess = "/";

    /**
     * 로그아웃 페이지 URL
     */
    private String logoutPage = "/logout";

    /**
     * 단일 OTT 인증 URL 설정
     */
    @NestedConfigurationProperty
    private SingleOttUrls ott = new SingleOttUrls();

    /**
     * 단일 Passkey 인증 URL 설정
     */
    @NestedConfigurationProperty
    private SinglePasskeyUrls passkey = new SinglePasskeyUrls();
}
