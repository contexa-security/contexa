package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.enums.AuthType;

/**
 * 단일 Passkey 인증 어댑터
 */
public class PasskeyAuthenticationAdapter extends BasePasskeyAuthenticationAdapter {

    @Override
    public String getId() {
        return AuthType.PASSKEY.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 400;
    }
}

