package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

/**
 * 단일 REST 인증 어댑터
 */
public final class RestAuthenticationAdapter extends BaseRestAuthenticationAdapter<RestAuthenticationConfigurer<HttpSecurity>> {

    @Override
    public String getId() {
        return AuthType.REST.name().toLowerCase();
    }

    @Override
    protected RestAuthenticationConfigurer createConfigurer() {
        return new RestAuthenticationConfigurer();
    }

    @Override
    protected void configureRestAuthentication(RestAuthenticationConfigurer configurer,
                                               RestOptions opts,
                                               PlatformAuthenticationSuccessHandler successHandler,
                                               PlatformAuthenticationFailureHandler failureHandler) {

        configurer.loginProcessingUrl(opts.getLoginProcessingUrl());

        if (opts.getSuccessHandler() != null) {
            configurer.successHandler(opts.getSuccessHandler());
        }
        if (opts.getFailureHandler() != null) {
            configurer.failureHandler(opts.getFailureHandler());
        }
    }

    @Override
    protected void configureSecurityContext(RestAuthenticationConfigurer configurer,
                                            RestOptions opts) {
        configurer.securityContextRepository(opts.getSecurityContextRepository());
    }
}