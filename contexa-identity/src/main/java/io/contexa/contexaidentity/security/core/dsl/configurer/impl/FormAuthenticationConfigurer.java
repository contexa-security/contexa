package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.FormAuthenticationFilter;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

/**
 * 단일 Form 인증 설정 클래스 (MFA 없음)
 */
public final class FormAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractFormAuthenticationConfigurer<FormAuthenticationConfigurer<H>, H> {

    @Override
    protected BaseAuthenticationFilter createAuthenticationFilter(
            H http,
            AuthenticationManager authenticationManager,
            ApplicationContext applicationContext,
            AuthContextProperties properties) {

        return new FormAuthenticationFilter(
                requestMatcher,
                authenticationManager,
                properties
        );
    }
}
