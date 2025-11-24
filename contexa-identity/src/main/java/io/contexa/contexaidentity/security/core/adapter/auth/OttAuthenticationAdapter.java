package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.enums.AuthType;

/**
 * 단일 OTT 인증 어댑터
 */
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
