package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.enums.AuthType;


public class MfaOttAuthenticationAdapter extends BaseOttAuthenticationAdapter {

    @Override
    public String getId() {
        return AuthType.MFA_OTT.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 301;
    }
}
