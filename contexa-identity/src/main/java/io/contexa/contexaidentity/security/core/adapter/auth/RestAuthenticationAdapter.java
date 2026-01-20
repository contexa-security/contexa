package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.filter.DefaultRestLoginPageGeneratingFilter;
import io.contexa.contexaidentity.security.filter.RestAuthenticationFilter;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


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

    @Override
    protected void configureHttpSecurity(HttpSecurity http, RestOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {
        super.configureHttpSecurity(http, opts, currentFlow, successHandler, failureHandler);

        DefaultRestLoginPageGeneratingFilter loginPageFilter = new DefaultRestLoginPageGeneratingFilter();
        http.addFilterBefore(loginPageFilter, UsernamePasswordAuthenticationFilter.class);
    }
}