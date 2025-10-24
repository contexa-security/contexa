package io.contexa.contexaiam.security.core.session;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Redis 세션 ID 추출 구현체
 *
 * Spring Session이 Redis에 저장한 세션 ID를 다양한 소스에서 추출합니다.
 * HttpSession.getId()가 아닌 실제 Redis 세션 ID를 반환합니다.
 *
 * @author AI3Security
 * @since 1.0
 */
@Slf4j
@Component
public class RedisSessionIdResolver implements SessionIdResolver {

    private static final String DEFAULT_SESSION_COOKIE_NAME = "SESSION";
    private static final String SESSION_ATTRIBUTE_NAME = "org.springframework.session.SessionRepository.CURRENT_SESSION_ID";
    private static final Pattern SESSION_ID_PATTERN = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    @Value("${server.servlet.session.cookie.name:SESSION}")
    private String sessionCookieName;

    @Value("${security.session.header.name:X-Auth-Token}")
    private String sessionHeaderName;

    @Value("${security.session.bearer.enabled:true}")
    private boolean bearerTokenEnabled;

    private final RedisTemplate<String, Object> redisTemplate;

    public RedisSessionIdResolver(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public String resolve(HttpServletRequest request) {
        String sessionId = null;
        SessionSource source = SessionSource.NONE;

        // 1. Cookie 에서 추출 (Spring Session 기본)
        sessionId = extractFromCookie(request);
        if (StringUtils.hasText(sessionId)) {
            source = SessionSource.COOKIE;
            log.trace("Session ID extracted from cookie: {}", maskSessionId(sessionId));
            return sessionId;
        }

        // 2. Custom Header 에서 추출 (API 클라이언트)
        sessionId = extractFromHeader(request);
        if (StringUtils.hasText(sessionId)) {
            source = SessionSource.HEADER;
            log.trace("Session ID extracted from header: {}", maskSessionId(sessionId));
            return sessionId;
        }

        // 3. Bearer Token 에서 추출 (JWT 또는 Opaque Token)
        if (bearerTokenEnabled) {
            sessionId = extractFromBearerToken(request);
            if (StringUtils.hasText(sessionId)) {
                source = SessionSource.BEARER;
                log.trace("Session ID extracted from bearer token: {}", maskSessionId(sessionId));
                return sessionId;
            }
        }

        // 4. Request Attribute 에서 추출 (Spring Session 내부)
        sessionId = extractFromAttribute(request);
        if (StringUtils.hasText(sessionId)) {
            source = SessionSource.ATTRIBUTE;
            log.trace("Session ID extracted from attribute: {}", maskSessionId(sessionId));
            return sessionId;
        }

        log.debug("No session ID found in request");
        return null;
    }

    @Override
    public boolean isValid(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return false;
        }

        // UUID 형식 검증
        if (!SESSION_ID_PATTERN.matcher(sessionId).matches()) {
            log.debug("Invalid session ID format: {}", maskSessionId(sessionId));
            return false;
        }

        // Redis에 실제로 존재하는지 확인
        String redisKey = "spring:session:sessions:" + sessionId;
        Boolean exists = redisTemplate.hasKey(redisKey);

        if (Boolean.FALSE.equals(exists)) {
            log.debug("Session ID not found in Redis: {}", maskSessionId(sessionId));
            return false;
        }

        // 만료 시간 확인
        Long ttl = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
        if (ttl != null && ttl <= 0) {
            log.debug("Session ID expired: {}", maskSessionId(sessionId));
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
        if (bearerTokenEnabled && extractFromBearerToken(request) != null) {
            return SessionSource.BEARER;
        }
        if (extractFromAttribute(request) != null) {
            return SessionSource.ATTRIBUTE;
        }
        return SessionSource.NONE;
    }

    /**
     * Cookie에서 세션 ID 추출
     */
    private String extractFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (sessionCookieName.equals(cookie.getName())) {
                String cookieValue = cookie.getValue();
                // Base64로 인코딩된 경우 디코딩
                if (isBase64Encoded(cookieValue)) {
                    try {
                        cookieValue = new String(Base64.getUrlDecoder().decode(cookieValue));
                    } catch (Exception e) {
                        log.debug("Failed to decode session cookie: {}", e.getMessage());
                    }
                }
                return cookieValue;
            }
        }

        return null;
    }

    /**
     * Header에서 세션 ID 추출
     */
    private String extractFromHeader(HttpServletRequest request) {
        String sessionId = request.getHeader(sessionHeaderName);
        if (StringUtils.hasText(sessionId)) {
            // "Bearer " 접두사 제거 (있는 경우)
            if (sessionId.startsWith("Bearer ")) {
                sessionId = sessionId.substring(7);
            }
            return sessionId.trim();
        }
        return null;
    }

    /**
     * Authorization Bearer Token에서 세션 ID 추출
     */
    private String extractFromBearerToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String token = authorization.substring(7).trim();

            // JWT인 경우 claims에서 sessionId 추출
            if (isJwtToken(token)) {
                return extractSessionIdFromJwt(token);
            }

            // Opaque Token인 경우 그대로 반환
            return token;
        }
        return null;
    }

    /**
     * Request Attribute에서 세션 ID 추출
     */
    private String extractFromAttribute(HttpServletRequest request) {
        Object sessionId = request.getAttribute(SESSION_ATTRIBUTE_NAME);
        if (sessionId instanceof String) {
            return (String) sessionId;
        }

        // Spring Session의 다른 속성들도 체크
        sessionId = request.getAttribute("sessionId");
        if (sessionId instanceof String) {
            return (String) sessionId;
        }

        return null;
    }

    /**
     * JWT 토큰인지 확인
     */
    private boolean isJwtToken(String token) {
        return token != null && token.split("\\.").length == 3;
    }

    /**
     * JWT에서 세션 ID 추출 (간단한 구현)
     */
    private String extractSessionIdFromJwt(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                return null;
            }

            // Payload 디코딩
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            // JSON에서 sessionId 추출 (간단한 구현)
            if (payload.contains("\"sessionId\":\"")) {
                int start = payload.indexOf("\"sessionId\":\"") + 13;
                int end = payload.indexOf("\"", start);
                if (end > start) {
                    return payload.substring(start, end);
                }
            }
        } catch (Exception e) {
            log.debug("Failed to extract session ID from JWT: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Base64 인코딩 여부 확인
     */
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

    /**
     * 세션 ID 마스킹 (로깅용)
     */
    private String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 8) {
            return "***";
        }
        return sessionId.substring(0, 4) + "..." + sessionId.substring(sessionId.length() - 4);
    }
}