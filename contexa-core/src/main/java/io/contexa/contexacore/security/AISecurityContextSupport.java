package io.contexa.contexacore.security;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
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
     * Priority: SessionIdResolver -> HttpSession -> JWT jti -> userId fallback.
     */
    public String resolveIdentifier(HttpServletRequest request, @Nullable Authentication auth) {
        if (sessionIdResolver != null) {
            String resolved = sessionIdResolver.resolve(request);
            if (resolved != null) {
                return resolved;
            }
        }

        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            String jti = jwtAuth.getToken().getId();
            if (jti != null) {
                return jti;
            }
        }

        HttpSession session = request.getSession(false);
        if (session != null) {
            return session.getId();
        }
        return auth != null ? auth.getName() : null;
    }

    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    public SecurityZeroTrustProperties getProperties() {
        return securityZeroTrustProperties;
    }
}
