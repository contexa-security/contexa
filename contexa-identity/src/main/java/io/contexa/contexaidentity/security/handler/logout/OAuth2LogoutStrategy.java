package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexaidentity.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;

@Slf4j
public class OAuth2LogoutStrategy implements LogoutStrategy {

    private static final String REASON_LOGOUT = "LOGOUT";

    private final TokenService tokenService;

    public OAuth2LogoutStrategy(TokenService tokenService) {
        Assert.notNull(tokenService, "tokenService cannot be null");
        this.tokenService = tokenService;
    }

    @Override
    public boolean supports(HttpServletRequest request, Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken) {
            return true;
        }
        return tokenService.resolveAccessToken(request) != null
                || tokenService.resolveRefreshToken(request) != null;
    }

    @Override
    public void execute(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String refreshToken = tokenService.resolveRefreshToken(request);
        String username = (authentication != null) ? authentication.getName() : "UNKNOWN";

        if (refreshToken == null) {
            return;
        }

        try {
            tokenService.invalidateRefreshToken(refreshToken);
            tokenService.blacklistRefreshToken(refreshToken, username, REASON_LOGOUT);
        } catch (AuthenticationException ex) {
            log.error("Failed to invalidate tokens during logout for user {}: {}", username, ex.getMessage());
        } catch (Exception ex) {
            log.error("Unexpected error during token invalidation for user {}: {}", username, ex.getMessage(), ex);
        }
    }
}
