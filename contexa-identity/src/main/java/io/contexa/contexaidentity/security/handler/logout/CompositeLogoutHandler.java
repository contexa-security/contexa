package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;

import java.util.List;

/**
 * LogoutHandler responsible for executing logout strategies and clearing token cookies.
 * Does NOT write response body - that is the responsibility of LogoutSuccessHandler.
 */
@Slf4j
public class CompositeLogoutHandler implements LogoutHandler, IForceLogoutService {

    private final List<LogoutStrategy> strategies;
    private final TokenService tokenService;
    private final ZeroTrustSecurityService zeroTrustSecurityService;
    private final DeviceAwareOAuth2AuthorizationService authorizationService;

    public CompositeLogoutHandler(
            List<LogoutStrategy> strategies,
            TokenService tokenService,
            ZeroTrustSecurityService zeroTrustSecurityService,
            DeviceAwareOAuth2AuthorizationService authorizationService) {

        Assert.notEmpty(strategies, "strategies cannot be empty");
        Assert.notNull(tokenService, "tokenService cannot be null");
        this.strategies = strategies;
        this.tokenService = tokenService;
        this.zeroTrustSecurityService = zeroTrustSecurityService;
        this.authorizationService = authorizationService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            for (LogoutStrategy strategy : strategies) {
                if (strategy.supports(request, authentication)) {
                    strategy.execute(request, response, authentication);
                }
            }
        } catch (Exception ex) {
            log.error("Error during logout: {}", ex.getMessage(), ex);
        } finally {
            SecurityContextHolder.clearContext();
            clearTokenCookies(response);
        }
    }

    @Override
    public void forceLogoutByUserId(String userId, String reason) {
        if (userId == null || userId.isBlank()) {
            return;
        }

        log.error("[ForceLogout] Executing force-logout: userId={}, reason={}", userId, reason);

        if (zeroTrustSecurityService != null) {
            try {
                zeroTrustSecurityService.invalidateAllUserSessions(userId, reason);
            } catch (Exception e) {
                log.error("[ForceLogout] Failed to invalidate ZeroTrust sessions: userId={}", userId, e);
            }

            try {
                zeroTrustSecurityService.cleanupOnLogout(userId, null);
            } catch (Exception e) {
                log.error("[ForceLogout] Failed to cleanup ZeroTrust Redis data: userId={}", userId, e);
            }
        }

        try {
            authorizationService.invalidateAllByPrincipalName(userId);
        } catch (Exception e) {
            log.error("[ForceLogout] Failed to invalidate OAuth2 authorizations: userId={}", userId, e);
        }
    }

    private void clearTokenCookies(HttpServletResponse response) {
        try {
            TokenTransportResult clearResult = tokenService.prepareClearTokens();
            if (clearResult.getCookiesToRemove() != null) {
                for (ResponseCookie cookie : clearResult.getCookiesToRemove()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
        } catch (Exception e) {
            log.error("Error clearing token cookies: {}", e.getMessage());
        }
    }
}
