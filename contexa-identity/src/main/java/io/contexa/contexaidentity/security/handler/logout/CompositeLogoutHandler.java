/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;

import java.util.List;

/**
 * LogoutHandler responsible for executing logout strategies and clearing token cookies.
 * Does NOT write response body - that is the responsibility of LogoutSuccessHandler.
 * Where Contexa's OAuth2 plane is not there, it has no token service and no authorization service: a sign-out then runs
 * its strategies on the session alone, and a forced sign-out ends the sessions only.
 */
@Slf4j
public class CompositeLogoutHandler implements LogoutHandler, IForceLogoutService {

    private final List<LogoutStrategy> strategies;
    @Nullable
    private final TokenService tokenService;
    private final ZeroTrustSecurityService zeroTrustSecurityService;
    @Nullable
    private final DeviceAwareOAuth2AuthorizationService authorizationService;

    public CompositeLogoutHandler(
            List<LogoutStrategy> strategies,
            @Nullable TokenService tokenService,
            ZeroTrustSecurityService zeroTrustSecurityService,
            @Nullable DeviceAwareOAuth2AuthorizationService authorizationService) {

        Assert.notEmpty(strategies, "strategies cannot be empty");
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

        log.warn("[ForceLogout] Executing force-logout: userId={}, reason={}", userId, reason);

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

        if (authorizationService == null) {
            return;
        }
        try {
            authorizationService.invalidateAllByPrincipalName(userId);
        } catch (Exception e) {
            log.error("[ForceLogout] Failed to invalidate OAuth2 authorizations: userId={}", userId, e);
        }
    }

    private void clearTokenCookies(HttpServletResponse response) {
        if (tokenService == null) {
            return;
        }
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
