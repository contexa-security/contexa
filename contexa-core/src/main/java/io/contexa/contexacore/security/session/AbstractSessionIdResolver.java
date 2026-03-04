package io.contexa.contexacore.security.session;

import io.contexa.contexacore.properties.SecuritySessionProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Abstract base for SessionIdResolver implementations.
 * Provides common resolve/extract logic for Cookie, Header, Bearer Token, and Attribute sources.
 * Subclasses implement session validation and attribute name configuration.
 */
@Slf4j
public abstract class AbstractSessionIdResolver implements SessionIdResolver {

    protected static final Pattern UUID_PATTERN =
            Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    protected final SecuritySessionProperties sessionProperties;

    protected AbstractSessionIdResolver(SecuritySessionProperties sessionProperties) {
        this.sessionProperties = sessionProperties;
    }

    /**
     * Validate session beyond UUID pattern check.
     * InMemory: always true (Spring Session manages validity).
     * Redis: checks Redis key existence and TTL.
     */
    protected abstract boolean validateSession(String sessionId);

    /**
     * Return request attribute names to check for session ID extraction.
     */
    protected abstract String[] getSessionAttributeNames();

    @Override
    public String resolve(HttpServletRequest request) {
        String sessionId = extractFromCookie(request);
        if (sessionId != null) {
            return sessionId;
        }

        sessionId = extractFromHeader(request);
        if (sessionId != null) {
            return sessionId;
        }

        if (sessionProperties.getBearer().isEnabled()) {
            sessionId = extractFromBearerToken(request);
            if (sessionId != null) {
                return sessionId;
            }
        }

        return extractFromAttribute(request);
    }

    @Override
    public final boolean isValid(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return false;
        }
        if (!UUID_PATTERN.matcher(sessionId).matches()) {
            return false;
        }
        return validateSession(sessionId);
    }

    @Override
    public SessionSource getSource(HttpServletRequest request) {
        if (extractFromCookie(request) != null) {
            return SessionSource.COOKIE;
        }
        if (extractFromHeader(request) != null) {
            return SessionSource.HEADER;
        }
        if (sessionProperties.getBearer().isEnabled() && extractFromBearerToken(request) != null) {
            return SessionSource.BEARER;
        }
        if (extractFromAttribute(request) != null) {
            return SessionSource.ATTRIBUTE;
        }
        return SessionSource.NONE;
    }

    private String extractFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        String cookieName = sessionProperties.getCookie().getName();
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                String value = cookie.getValue();
                if (StringUtils.hasText(value)) {
                    return tryBase64Decode(value);
                }
            }
        }
        return null;
    }

    private String extractFromHeader(HttpServletRequest request) {
        String headerName = sessionProperties.getHeader().getName();
        String value = request.getHeader(headerName);
        if (StringUtils.hasText(value)) {
            if (value.startsWith("Bearer ")) {
                value = value.substring(7);
            }
            return value.trim();
        }
        return null;
    }

    private String extractFromBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7).trim();
            if (isJwtToken(token)) {
                return null;
            }
            return token;
        }
        return null;
    }

    private String extractFromAttribute(HttpServletRequest request) {
        for (String attrName : getSessionAttributeNames()) {
            Object attr = request.getAttribute(attrName);
            if (attr instanceof String s && StringUtils.hasText(s)) {
                return s;
            }
        }
        return null;
    }

    private String tryBase64Decode(String value) {
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(value));
            if (UUID_PATTERN.matcher(decoded).matches()) {
                return decoded;
            }
        } catch (Exception ignored) {
            // not URL-safe Base64
        }

        try {
            String decoded = new String(Base64.getDecoder().decode(value));
            if (UUID_PATTERN.matcher(decoded).matches()) {
                return decoded;
            }
        } catch (Exception ignored) {
            // not standard Base64
        }

        return value;
    }

    private boolean isJwtToken(String token) {
        return token != null && token.split("\\.").length == 3;
    }
}
