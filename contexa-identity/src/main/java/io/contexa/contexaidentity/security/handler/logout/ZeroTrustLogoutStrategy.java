package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

@Slf4j
public class ZeroTrustLogoutStrategy implements LogoutStrategy {

    private final ZeroTrustSecurityService zeroTrustSecurityService;
    private final SessionIdResolver sessionIdResolver;

    public ZeroTrustLogoutStrategy(
            ZeroTrustSecurityService zeroTrustSecurityService,
            SessionIdResolver sessionIdResolver) {
        this.zeroTrustSecurityService = zeroTrustSecurityService;
        this.sessionIdResolver = sessionIdResolver;
    }

    @Override
    public boolean supports(HttpServletRequest request, Authentication authentication) {
        return authentication != null && authentication.isAuthenticated();
    }

    @Override
    public void execute(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) {
        String userId = authentication.getName();
        String sessionId = sessionIdResolver.resolve(request);
        try {
            zeroTrustSecurityService.cleanupOnLogout(userId, sessionId);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to cleanup Redis on logout: userId={}", userId, e);
        }
    }
}
