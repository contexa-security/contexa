package io.contexa.contexacore.security.session;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import io.contexa.contexacore.properties.SecuritySessionProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.util.StringUtils;

import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

@Slf4j
public class RedisSessionIdResolver implements SessionIdResolver {

    private static final String SESSION_ATTRIBUTE_NAME = "org.springframework.session.SessionRepository.CURRENT_SESSION_ID";
    private static final Pattern SESSION_ID_PATTERN = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    @Value("${server.servlet.session.cookie.name:SESSION}")
    private String sessionCookieName;

    private final RedisTemplate<String, Object> redisTemplate;
    private final SecuritySessionProperties securitySessionProperties;

    public RedisSessionIdResolver(RedisTemplate<String, Object> redisTemplate,
                                  SecuritySessionProperties securitySessionProperties) {
        this.redisTemplate = redisTemplate;
        this.securitySessionProperties = securitySessionProperties;
    }

    @Override
    public String resolve(HttpServletRequest request) {
        String sessionId;
        sessionId = extractFromCookie(request);
        if (StringUtils.hasText(sessionId)) {
            return sessionId;
        }

        sessionId = extractFromHeader(request);
        if (StringUtils.hasText(sessionId)) {
            return sessionId;
        }

        if (securitySessionProperties.getBearer().isEnabled()) {
            sessionId = extractFromBearerToken(request);
            if (StringUtils.hasText(sessionId)) {
                return sessionId;
            }
        }

        sessionId = extractFromAttribute(request);
        if (StringUtils.hasText(sessionId)) {
            return sessionId;
        }

        return null;
    }

    @Override
    public boolean isValid(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return false;
        }

        if (!SESSION_ID_PATTERN.matcher(sessionId).matches()) {
            return false;
        }

        String redisKey = "spring:session:sessions:" + sessionId;
        Boolean exists = redisTemplate.hasKey(redisKey);

        if (Boolean.FALSE.equals(exists)) {
            return false;
        }

        Long ttl = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
        if (ttl != null && ttl <= 0) {
            return false;
        }

        return true;
    }

    @Override
    public SessionSource getSource(HttpServletRequest request) {
        if (extractFromCookie(request) != null) {
            return SessionSource.COOKIE;
        }
        if (extractFromHeader(request) != null) {
            return SessionSource.HEADER;
        }
        if (securitySessionProperties.getBearer().isEnabled() && extractFromBearerToken(request) != null) {
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

        for (Cookie cookie : cookies) {
            if (sessionCookieName.equals(cookie.getName())) {
                String cookieValue = cookie.getValue();

                if (isBase64Encoded(cookieValue)) {
                    try {
                        cookieValue = new String(Base64.getUrlDecoder().decode(cookieValue));
                    } catch (Exception e) {
                    }
                }
                return cookieValue;
            }
        }

        return null;
    }

    private String extractFromHeader(HttpServletRequest request) {
        String sessionId = request.getHeader(securitySessionProperties.getHeader().getName());
        if (StringUtils.hasText(sessionId)) {

            if (sessionId.startsWith("Bearer ")) {
                sessionId = sessionId.substring(7);
            }
            return sessionId.trim();
        }
        return null;
    }

    private String extractFromBearerToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String token = authorization.substring(7).trim();

            if (isJwtToken(token)) {
                return null;
            }

            return token;
        }
        return null;
    }

    private String extractFromAttribute(HttpServletRequest request) {
        Object sessionId = request.getAttribute(SESSION_ATTRIBUTE_NAME);
        if (sessionId instanceof String) {
            return (String) sessionId;
        }

        sessionId = request.getAttribute("sessionId");
        if (sessionId instanceof String) {
            return (String) sessionId;
        }

        return null;
    }

    private boolean isJwtToken(String token) {
        return token != null && token.split("\\.").length == 3;
    }

    private boolean isBase64Encoded(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        try {
            Base64.getUrlDecoder().decode(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 8) {
            return "***";
        }
        return sessionId.substring(0, 4) + "..." + sessionId.substring(sessionId.length() - 4);
    }
}