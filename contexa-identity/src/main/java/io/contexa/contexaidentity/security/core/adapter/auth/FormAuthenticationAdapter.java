package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public final class FormAuthenticationAdapter extends AbstractAuthenticationAdapter<FormOptions> {

    @Override
    public String getId() {
        return AuthType.FORM.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 100;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, FormOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {
        http.formLogin(form -> {
            form.loginPage(opts.getLoginPage())
                    .loginProcessingUrl(opts.getLoginProcessingUrl())
                    .usernameParameter(opts.getUsernameParameter())
                    .passwordParameter(opts.getPasswordParameter())
                    .failureUrl(opts.getFailureUrl())
                    .permitAll(opts.isPermitAll())
                    .successHandler(successHandler)
                    .failureHandler(failureHandler);

            if (opts.getSecurityContextRepository() != null) {
                form.securityContextRepository(opts.getSecurityContextRepository());
            }

            SafeHttpFormLoginCustomizer rawLogin = opts.getRawFormLoginCustomizer();
            if (rawLogin != null) {
                try {
                    rawLogin.customize(form);
                } catch (Exception e) {
                    throw new RuntimeException("Error customizing raw form login for " + getId(), e);
                }
            }
        });
    }
}
