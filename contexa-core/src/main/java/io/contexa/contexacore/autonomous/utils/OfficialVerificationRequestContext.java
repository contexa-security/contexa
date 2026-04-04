package io.contexa.contexacore.autonomous.utils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Resolves session ID and user ID from the current HTTP request.
 * Used by HCAD, RequestInfoExtractor, and ZeroTrustEventPublisher
 * to obtain consistent identity information across the security plane.
 */
public final class OfficialVerificationRequestContext {

    private static final String USER_ID_HEADER = "X-Contexa-User-Id";
    private static final String USER_ID_ATTRIBUTE = "contexa.userId";

    private OfficialVerificationRequestContext() {}

    /**
     * Resolve session ID from the request.
     * Returns existing session ID without creating a new session.
     */
    public static String resolveSessionId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        HttpSession session = request.getSession(false);
        return session != null ? session.getId() : null;
    }

    /**
     * Resolve user ID from the request.
     * Checks request attribute, header, then SecurityContext in order.
     */
    public static String resolveUserId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object attrUserId = request.getAttribute(USER_ID_ATTRIBUTE);
        if (attrUserId != null && !attrUserId.toString().isBlank()) {
            return attrUserId.toString();
        }
        String headerUserId = request.getHeader(USER_ID_HEADER);
        if (headerUserId != null && !headerUserId.isBlank()) {
            return headerUserId;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth.getName() != null) {
            return auth.getName();
        }
        return null;
    }
}
