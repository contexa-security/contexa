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


public class OAuth2PreAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    public OAuth2PreAuthenticationFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        
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
