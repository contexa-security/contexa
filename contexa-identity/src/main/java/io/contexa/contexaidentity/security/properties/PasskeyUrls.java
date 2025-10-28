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

    // === Legacy WebAuthn URLs (Spring Security defaults) ===

    /**
     * 레거시 WebAuthn assertion options URL
     * @deprecated Use ApiUrls.assertionOptions instead
     */
    @Deprecated
    private String assertionOptions = "/webauthn/assertion/options";

    /**
     * 레거시 WebAuthn registration options URL
     */
    private String registrationOptions = "/webauthn/registration/options";
}
