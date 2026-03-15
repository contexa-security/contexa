package io.contexa.contexacore.security.zerotrust;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.context.SecurityContext;

public interface ZeroTrustSecurityService {

    void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId, HttpServletRequest request);

    void invalidateSession(String sessionId, String userId, String reason);

    boolean isSessionInvalidated(String sessionId);

    void cleanupOnLogout(String userId, String sessionId);

    void invalidateAllUserSessions(String userId, String reason);

    default void invalidateDecisionCache(String userId) {}
}
