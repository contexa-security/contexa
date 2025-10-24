package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.RestAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

public final class RestAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractRestAuthenticationConfigurer<RestAuthenticationConfigurer<H>, H> {

    @Override
    protected BaseAuthenticationFilter createAuthenticationFilter(
            H http,
            AuthenticationManager authenticationManager,
            ApplicationContext applicationContext,
            AuthContextProperties properties) {

        // MFA 세션 관리를 위한 의존성 주입
        MfaSessionRepository sessionRepository = applicationContext.getBean(MfaSessionRepository.class);
        MfaStateMachineIntegrator stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        return new RestAuthenticationFilter(
                requestMatcher,
                authenticationManager,
                properties,
                sessionRepository,
                stateMachineIntegrator
        );
    }
}