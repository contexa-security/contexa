package io.contexa.contexacore.autonomous.utils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
<<<<<<< Updated upstream
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
=======
import org.springframework.util.StringUtils;

public final class OfficialVerificationRequestContext {

    public static final String REQUESTED_USER_ID = "officialVerification.requestedUserId";
    public static final String SYNTHETIC_SESSION_ID = "officialVerification.sessionId";
    private static final String HCAD_USER_ID = "hcad.user_id";
    private static final String HCAD_USER_ID_CAMEL = "hcad.userId";
    private static final String HCAD_SESSION_ID = "hcad.session_id";
    private static final String HCAD_SESSION_ID_CAMEL = "hcad.sessionId";

    private OfficialVerificationRequestContext() {
    }

    public static void apply(HttpServletRequest request, String requestedUserId, String syntheticSessionId) {
        if (request == null) {
            return;
        }
        putIfText(request, REQUESTED_USER_ID, requestedUserId);
        putIfText(request, HCAD_USER_ID, requestedUserId);
        putIfText(request, HCAD_USER_ID_CAMEL, requestedUserId);
        putIfText(request, SYNTHETIC_SESSION_ID, syntheticSessionId);
        putIfText(request, HCAD_SESSION_ID, syntheticSessionId);
        putIfText(request, HCAD_SESSION_ID_CAMEL, syntheticSessionId);
    }

>>>>>>> Stashed changes
    public static String resolveUserId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
<<<<<<< Updated upstream
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
=======
        return firstTextAttribute(
                request,
                REQUESTED_USER_ID,
                HCAD_USER_ID,
                HCAD_USER_ID_CAMEL
        );
    }

    public static String resolveSessionId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String override = firstTextAttribute(
                request,
                SYNTHETIC_SESSION_ID,
                HCAD_SESSION_ID,
                HCAD_SESSION_ID_CAMEL
        );
        if (StringUtils.hasText(override)) {
            return override.trim();
        }

        HttpSession session = request.getSession(false);
        if (session != null && StringUtils.hasText(session.getId())) {
            return session.getId().trim();
        }

        String requestedSessionId = request.getRequestedSessionId();
        return StringUtils.hasText(requestedSessionId) ? requestedSessionId.trim() : null;
    }

    private static void putIfText(HttpServletRequest request, String name, String value) {
        if (request != null && StringUtils.hasText(name) && StringUtils.hasText(value)) {
            request.setAttribute(name, value.trim());
        }
    }

    private static String firstTextAttribute(HttpServletRequest request, String... attributeNames) {
        if (request == null || attributeNames == null) {
            return null;
        }
        for (String attributeName : attributeNames) {
            Object value = request.getAttribute(attributeName);
            if (value instanceof String text && StringUtils.hasText(text)) {
                return text.trim();
            }
>>>>>>> Stashed changes
        }
        return null;
    }
}
