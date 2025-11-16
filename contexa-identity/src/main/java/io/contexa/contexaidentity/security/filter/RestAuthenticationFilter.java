package io.contexa.contexaidentity.security.filter;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.io.IOException;

/**
 * 단일 REST 인증 필터 (MFA 없음)
 *
 * REST API 표준 인증 처리
 * - JSON Body에서 username/password 읽기
 * - RestAuthenticationToken 사용
 * - MFA 로직 없음 (FactorContext, State Machine 제외)
 * - OAuth2 토큰 기반 핸들러 기본 탑재
 */
@Slf4j
public class RestAuthenticationFilter extends BaseAuthenticationFilter {

    public RestAuthenticationFilter(RequestMatcher requestMatcher,
                                    AuthenticationManager authenticationManager,
                                    AuthContextProperties properties,
                                    TokenService tokenService,
                                    AuthResponseWriter responseWriter) {
        super(requestMatcher, authenticationManager, properties);

        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(properties, "properties cannot be null");
        Assert.notNull(tokenService, "tokenService cannot be null");
        Assert.notNull(responseWriter, "responseWriter cannot be null");

        log.info("RestAuthenticationFilter initialized with OAuth2 token-based handlers");
    }

    /**
     * 인증 성공 처리 - 단순 Security Context 저장 (MFA 없음)
     */
    @Override
    public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {

        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        log.info("REST authentication successful for user: {}", authentication.getName());
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    /**
     * 인증 실패 처리
     */
    @Override
    public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();

        log.warn("REST authentication failed from IP: {}. Error: {}",
                getClientIpAddress(request),
                failed.getMessage());

        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
