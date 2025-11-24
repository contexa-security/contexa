package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.RestAuthenticationFilter;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

/**
 * 단일 REST 인증 설정 클래스 (MFA 없음)
 */
public final class RestAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractRestAuthenticationConfigurer<RestAuthenticationConfigurer<H>, H> {

    @Override
    protected BaseAuthenticationFilter createAuthenticationFilter(
            H http,
            AuthenticationManager authenticationManager,
            ApplicationContext applicationContext,
            AuthContextProperties properties) {

        // OAuth2 토큰 기반 핸들러를 위한 의존성 주입
        TokenService tokenService = applicationContext.getBean(TokenService.class);
        AuthResponseWriter responseWriter = applicationContext.getBean(AuthResponseWriter.class);

        return new RestAuthenticationFilter(
                requestMatcher,
                authenticationManager,
                properties,
                tokenService,
                responseWriter
        );
    }
}