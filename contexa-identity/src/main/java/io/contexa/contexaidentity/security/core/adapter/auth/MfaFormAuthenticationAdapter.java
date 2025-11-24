package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.dsl.configurer.impl.MfaFormAuthenticationConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

/**
 * MFA Form 인증 어댑터
 */
public final class MfaFormAuthenticationAdapter extends BaseFormAuthenticationAdapter<MfaFormAuthenticationConfigurer<HttpSecurity>> {

    @Override
    public String getId() {
        return AuthType.MFA_FORM.name().toLowerCase();
    }

    @Override
    protected MfaFormAuthenticationConfigurer<HttpSecurity> createConfigurer() {
        return new MfaFormAuthenticationConfigurer<>();
    }

    @Override
    protected void configureFormAuthentication(MfaFormAuthenticationConfigurer<HttpSecurity> configurer,
                                               FormOptions opts,
                                               PlatformAuthenticationSuccessHandler successHandler,
                                               PlatformAuthenticationFailureHandler failureHandler) {
        configurer
                .loginProcessingUrl(opts.getLoginProcessingUrl())
                .usernameParameter(opts.getUsernameParameter())
                .passwordParameter(opts.getPasswordParameter())
                .loginPage(opts.getLoginPage())
                .failureUrl(opts.getFailureUrl())
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll(opts.isPermitAll());
    }

    @Override
    protected void configureSecurityContext(MfaFormAuthenticationConfigurer<HttpSecurity> configurer,
                                            FormOptions opts) {
        configurer.securityContextRepository(opts.getSecurityContextRepository());
    }
}
