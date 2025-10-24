package io.contexa.contexaidentity.security.filter;

import io.contexa.contexaidentity.security.token.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * OAuth2 기반 Pre-Authentication 필터
 *
 * 로그아웃 엔드포인트(/api/auth/logout)에서만 동작하여 Access Token 검증 후
 * SecurityContext에 인증 정보를 설정합니다.
 *
 * JwtPreAuthenticationFilter와 동일한 역할을 OAuth2 환경에서 수행합니다.
 */
public class OAuth2PreAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    public OAuth2PreAuthenticationFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // 로그아웃 URI일 때만 access 토큰으로 인증 처리
        if ("/api/auth/logout".equals(request.getRequestURI())) {
            String token = tokenService.resolveAccessToken(request);
            if (StringUtils.hasText(token) && tokenService.validateAccessToken(token)) {
                Authentication authentication = tokenService.getAuthentication(token);

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }
}
