package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.dsl.configurer.impl.MfaRestAuthenticationConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public final class MfaRestAuthenticationAdapter extends BaseRestAuthenticationAdapter<MfaRestAuthenticationConfigurer<HttpSecurity>> {

    @Override
    public String getId() {
        return AuthType.MFA_REST.name().toLowerCase();
    }

    @Override
    protected MfaRestAuthenticationConfigurer createConfigurer() {
        return new MfaRestAuthenticationConfigurer();
    }

    @Override
    protected void configureRestAuthentication(MfaRestAuthenticationConfigurer configurer,
                                               RestOptions opts,
                                               PlatformAuthenticationSuccessHandler successHandler,
                                               PlatformAuthenticationFailureHandler failureHandler) {
        configurer.loginProcessingUrl(opts.getLoginProcessingUrl())
                .successHandler(successHandler)
                .failureHandler(failureHandler);
    }

    @Override
    protected void configureSecurityContext(MfaRestAuthenticationConfigurer configurer,
                                            RestOptions opts) {
        configurer.securityContextRepository(opts.getSecurityContextRepository());
    }
}