package io.contexa.contexaidentity.security.properties;

import lombok.Data;

/**
 * Passkey(WebAuthn) Factor URL 설정
 */
@Data
public class PasskeyUrls {
    // === MFA Flow URLs ===

    /**
     * Passkey 검증 처리 URL (POST) - Filter가 처리
     */
    private String loginProcessing = "/login/mfa-webauthn";

    /**
     * Passkey 챌린지 UI 페이지
     */
    private String challengeUi = "/mfa/challenge/passkey";

    /**
     * Passkey 검증 실패 기본 URL
     */
    private String defaultFailure = "/mfa/challenge/passkey?error";

    // === Passkey Registration URLs ===

    /**
     * Passkey 등록 요청 URL (POST)
     */
    private String registrationRequest = "/mfa/passkey/register-request";

    /**
     * Passkey 등록 처리 URL (POST)
     */
    private String registrationProcessing = "/mfa/passkey/register";

    // === WebAuthn Standard URLs (Spring Security) ===

    /**
     * WebAuthn assertion options URL (Spring Security 표준)
     * Passkey 인증 시 Assertion Options 요청
     *
     * Spring Security 6.x WebAuthn의 기본 엔드포인트: /webauthn/authenticate/options
     */
    private String assertionOptions = "/webauthn/authenticate/options";

    /**
     * WebAuthn registration options URL (Spring Security 표준)
     * Passkey 등록 시 Registration Options 요청
     */
    private String registrationOptions = "/webauthn/registration/options";
}
