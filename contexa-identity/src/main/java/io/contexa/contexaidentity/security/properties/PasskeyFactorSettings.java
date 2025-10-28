package io.contexa.contexaidentity.security.properties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PasskeyFactorSettings {
    private String loginProcessingUrl = "/login/mfa-webauthn"; // Passkey 인증 UI 및 처리 URL (GET & POST)
    private String challengeUrl = "/mfa/challenge/passkey"; // Passkey 인증 UI 및 처리 URL (GET & POST)
    private String defaultFailureUrl = "/mfa/challenge/passkey?error"; // Passkey 검증 실패 시 기본 리다이렉션 URL
    private int timeoutSeconds = 60; // Passkey assertion/registration timeout
    // Passkey 등록 UI URL
    private String registrationRequestUrl = "/mfa/passkey/register-request"; // GET, JS에서 사용
    private String registrationProcessingUrl = "/mfa/passkey/register"; // POST, Spring Security 필터 처리
    // WebAuthn 설정
    private String rpId = "localhost"; // Relying Party ID (기본값)
    private String rpName = "Contexa Platform"; // Relying Party Name (기본값)
}