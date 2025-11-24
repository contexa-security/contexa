package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.enums.AuthType;

/**
 * MFA Passkey 인증 어댑터
 *
 * 단일 인증 Passkey와 동일한 Spring Security WebAuthnAuthenticationFilter를 사용합니다.
 */
public class MfaPasskeyAuthenticationAdapter extends BasePasskeyAuthenticationAdapter {

    @Override
    public String getId() {
        return AuthType.MFA_PASSKEY.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 401;
    }
}
