package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.enums.AuthType;


public class OttAuthenticationAdapter extends BaseOttAuthenticationAdapter {

    @Override
    public String getId() {
        return AuthType.OTT.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 300;
    }
}
