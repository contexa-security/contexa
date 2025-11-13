package io.contexa.contexaidentity.security.properties;

import lombok.Data;

/**
 * 단일 Passkey(WebAuthn) 인증 URL 설정 (MFA 없는 독립 인증)
 */
@Data
public class SinglePasskeyUrls {
    /**
     * Passkey 로그인 페이지 (GET)
     */
    private String loginPage = "/login/webauthn";

    /**
     * Passkey 검증 처리 URL (POST)
     * Spring Security WebAuthnAuthenticationFilter가 처리
     * 기본값: /login/webauthn
     */
    private String loginProcessing = "/login/webauthn";

    /**
     * Passkey 검증 실패 리다이렉트 URL
     */
    private String loginFailure = "/login/webauthn?error";

    /**
     * WebAuthn assertion options URL (Spring Security 표준)
     * Passkey 인증 시 Assertion Options 요청
     * Spring Security 6.x WebAuthn 기본 엔드포인트
     */
    private String assertionOptions = "/webauthn/authenticate/options";

    /**
     * WebAuthn registration options URL (Spring Security 표준)
     * Passkey 등록 시 Registration Options 요청
     * Spring Security 6.x WebAuthn 기본 엔드포인트
     */
    private String registrationOptions = "/webauthn/register/options";

    /**
     * Passkey 등록 요청 URL (POST)
     */
    private String registrationRequest = "/passkey/register-request";

    /**
     * Passkey 등록 처리 URL (POST)
     */
    private String registrationProcessing = "/webauthn/register";
}
