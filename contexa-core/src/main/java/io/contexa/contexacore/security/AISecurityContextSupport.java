package io.contexa.contexacore.security;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;

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
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public AISecurityContextSupport(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            @Nullable ZeroTrustSecurityService zeroTrustSecurityService) {
        this.securityZeroTrustProperties = securityZeroTrustProperties;
        this.zeroTrustSecurityService = zeroTrustSecurityService;
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

    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    public SecurityZeroTrustProperties getProperties() {
        return securityZeroTrustProperties;
    }
}
