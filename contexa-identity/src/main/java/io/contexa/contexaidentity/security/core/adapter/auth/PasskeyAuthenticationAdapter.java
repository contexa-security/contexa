package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.enums.AuthType;

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

