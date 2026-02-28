package io.contexa.contexacore.security.session;

import io.contexa.contexacore.properties.SecuritySessionProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.Base64;
import java.util.regex.Pattern;

/**
 * In-memory implementation of SessionIdResolver for standalone mode.
 * Resolves session IDs from request without Redis validation.
 * Spring Session manages session validity internally.
 */
@Slf4j
@RequiredArgsConstructor
public class InMemorySessionIdResolver implements SessionIdResolver {

    private static final Pattern UUID_PATTERN =
            Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private final SecuritySessionProperties sessionProperties;

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

        sessionId = extractFromBearerToken(request);
        if (sessionId != null) {
            return sessionId;
        }

        return extractFromAttribute(request);
    }

    @Override
    public boolean isValid(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return false;
        }
        return UUID_PATTERN.matcher(sessionId).matches();
    }

    @Override
    public SessionSource getSource(HttpServletRequest request) {
        if (extractFromCookie(request) != null) {
            return SessionSource.COOKIE;
        }
        if (extractFromHeader(request) != null) {
            return SessionSource.HEADER;
        }
        if (extractFromBearerToken(request) != null) {
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
        return StringUtils.hasText(value) ? value : null;
    }

    private String extractFromBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (token.split("\\.").length != 3) {
                return token;
            }
        }
        return null;
    }

    private String extractFromAttribute(HttpServletRequest request) {
        Object attr = request.getAttribute("CONTEXA_SESSION_ID");
        return attr instanceof String s && StringUtils.hasText(s) ? s : null;
    }

    private String tryBase64Decode(String value) {
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            String decodedStr = new String(decoded);
            if (UUID_PATTERN.matcher(decodedStr).matches()) {
                return decodedStr;
            }
        } catch (Exception ignored) {
            // not base64 encoded
        }
        return value;
    }
}
