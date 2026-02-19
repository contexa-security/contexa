package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public abstract class BaseFormAuthenticationAdapter<T extends AbstractHttpConfigurer<T, HttpSecurity>>
        extends AbstractAuthenticationAdapter<FormOptions> {

    @Override
    public int getOrder() {
        return 100;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, FormOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {

        T configurer = createConfigurer();

        http.with(configurer, config -> {
            configureFormAuthentication(config, opts, successHandler, failureHandler);
            configureSecurityContext(config, opts);
        });
    }

    protected abstract T createConfigurer();

    protected abstract void configureFormAuthentication(T configurer, FormOptions opts,
                                                        PlatformAuthenticationSuccessHandler successHandler,
                                                        PlatformAuthenticationFailureHandler failureHandler);

    protected abstract void configureSecurityContext(T configurer, FormOptions opts);
}
