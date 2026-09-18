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
package io.contexa.contexacore.security;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.ClassUtils;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Shared Zero Trust logic delegated from AISessionSecurityContextRepository
 * and AIOAuth2SecurityContextRepository via composition pattern.
 * Avoids Java single-inheritance constraint between HttpSessionSecurityContextRepository
 * and RequestAttributeSecurityContextRepository.
 */
@Slf4j
public class AISecurityContextSupport {

    private static final boolean JWT_AUTHENTICATION_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken",
            AISecurityContextSupport.class.getClassLoader());

    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final ZeroTrustSecurityService zeroTrustSecurityService;
    private final SessionIdResolver sessionIdResolver;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public AISecurityContextSupport(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            @Nullable ZeroTrustSecurityService zeroTrustSecurityService,
            @Nullable SessionIdResolver sessionIdResolver) {
        this.securityZeroTrustProperties = securityZeroTrustProperties;
        this.zeroTrustSecurityService = zeroTrustSecurityService;
        this.sessionIdResolver = sessionIdResolver;
    }

    public boolean isEnabled() {
        return securityZeroTrustProperties.isEnabled();
    }

    public boolean isActuallyAuthenticated(Authentication auth) {
        if (auth == null || auth instanceof AnonymousAuthenticationToken) {
            return false;
        }
        return auth.isAuthenticated() && trustResolver.isAuthenticated(auth);
    }

    public void applyZeroTrust(SecurityContext context, String userId, String identifier, HttpServletRequest request) {
        if (zeroTrustSecurityService != null) {
            zeroTrustSecurityService.applyZeroTrustToContext(context, userId, identifier, request);
        }
    }

    public boolean isSessionInvalidated(String identifier) {
        if (zeroTrustSecurityService == null) {
            return false;
        }
        return zeroTrustSecurityService.isSessionInvalidated(identifier);
    }

    public void invalidateSession(String identifier, String userId, String reason) {
        if (zeroTrustSecurityService != null) {
            zeroTrustSecurityService.invalidateSession(identifier, userId, reason);
        }
    }

    public void invalidateAllUserSessions(String userId, String reason) {
        if (!securityZeroTrustProperties.isEnabled() || zeroTrustSecurityService == null) {
            return;
        }
        try {
            log.error("[ZeroTrust] Invalidating all sessions for user: {} - Reason: {}", userId, reason);
            zeroTrustSecurityService.invalidateAllUserSessions(userId, reason);
        } catch (Exception e) {
            log.error("[ZeroTrust] Error invalidating all sessions for user: {}", userId, e);
        }
    }

    /**
     * Resolve identifier from request and authentication context.
     * Prefer the authenticated JWT or actual HTTP session over request-carried identifiers.
     */
    public String resolveIdentifier(HttpServletRequest request, @Nullable Authentication auth) {
        if (JWT_AUTHENTICATION_PRESENT && auth instanceof JwtAuthenticationToken jwtAuth) {
            return jwtAuth.getToken().getId();
        }

        HttpSession session = request.getSession(false);
        if (session != null) {
            return session.getId();
        }
        return sessionIdResolver != null ? sessionIdResolver.resolve(request) : null;
    }

    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    public SecurityZeroTrustProperties getProperties() {
        return securityZeroTrustProperties;
    }
}
