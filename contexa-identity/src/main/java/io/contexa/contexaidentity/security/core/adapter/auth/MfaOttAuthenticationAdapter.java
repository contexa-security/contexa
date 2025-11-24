package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.enums.AuthType;

/**
 * MFA OTT 인증 어댑터
 *
 * 단일 인증 OTT와 동일한 Spring Security OneTimeTokenAuthenticationFilter를 사용합니다.
 */
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
