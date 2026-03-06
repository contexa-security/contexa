package io.contexa.contexacore.infra.session.impl;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.SessionIdGenerationException;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@ConditionalOnProperty(name = "spring.auth.mfa.session-storage-type", havingValue = "redis")
public class RedisMfaRepository implements MfaSessionRepository {

    private final StringRedisTemplate redisTemplate;
    private final SessionIdGenerator sessionIdGenerator;
    private final AuthContextProperties authContextProperties;

    private static final String SESSION_PREFIX = "mfa:session:v2:";
    private static final String COLLISION_COUNTER_KEY_PREFIX = "mfa:collision:counter:";
    private static final String SESSION_STATS_KEY = "mfa:stats:v2";
    private static final String COOKIE_NAME = "MFA_SID";
    private static final String TEMP_SESSION_ATTR = "_tempMfaSessionId_";
    private static final int MAX_COLLISION_RETRIES = 10;

    private Duration sessionTimeout;

    private final AtomicLong totalSessionsCreated = new AtomicLong(0);
    private final AtomicLong sessionCollisionsResolved = new AtomicLong(0);

    private static final String CREATE_SESSION_IF_NOT_EXISTS_SCRIPT =
            "local key_exists = redis.call('EXISTS', KEYS[1]) " +
                    "if key_exists == 0 then " +
                    "    redis.call('PSETEX', KEYS[1], ARGV[2], ARGV[1]) " +
                    "    return 1 " +
                    "else " +
                    "    return 0 " +
                    "end";

    public RedisMfaRepository(StringRedisTemplate redisTemplate, SessionIdGenerator sessionIdGenerator,
                              AuthContextProperties authContextProperties) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate cannot be null");
        this.sessionIdGenerator = Objects.requireNonNull(sessionIdGenerator, "sessionIdGenerator cannot be null");
        this.authContextProperties = Objects.requireNonNull(authContextProperties, "authContextProperties cannot be null");
    }

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        if (!isValidSessionIdFormat(sessionId)) {
            log.error("Invalid session ID format attempted for storage: {}", sessionId);
            throw new IllegalArgumentException("Invalid session ID format: " + sessionId);
        }

        String redisKey = SESSION_PREFIX + sessionId;
        String sessionValue = createSessionValue(sessionId, request);

        DefaultRedisScript<Long> script = new DefaultRedisScript<>(CREATE_SESSION_IF_NOT_EXISTS_SCRIPT, Long.class);
        Long result = redisTemplate.execute(script,
                Collections.singletonList(redisKey),
                sessionValue,
                String.valueOf(sessionTimeout.toMillis()));

        if (result == 1) {
            totalSessionsCreated.incrementAndGet();
            updateSessionStatsAsync();

            if (response != null) {
                setSessionCookie(response, sessionId, request.isSecure());
            }
            request.setAttribute(TEMP_SESSION_ATTR, sessionId);
        } else {

            log.error("Failed to store session ID {} in Redis. It might already exist or script failed. Result: {}", sessionId, result);
            throw new SessionIdGenerationException("Failed to exclusively store session ID in Redis: " + sessionId);
        }
    }

    @Override
    public String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request) {
        String repositoryTypeCollisionCounterKey = COLLISION_COUNTER_KEY_PREFIX + getRepositoryType();
        for (int attempt = 0; attempt < MAX_COLLISION_RETRIES; attempt++) {
            String sessionId = sessionIdGenerator.generate(baseId, request);

            if (isSessionIdUnique(sessionId)) {
                request.setAttribute(TEMP_SESSION_ATTR, sessionId);
                return sessionId;
            }
            log.error("Generated session ID {} was not unique or secure enough for Redis (attempt: {}). Retrying.",
                    sessionId, attempt + 1);

            try {
                Thread.sleep((long) (Math.pow(2, attempt) * 10));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SessionIdGenerationException("Session ID generation interrupted during collision retry", e);
            }
        }
        throw new SessionIdGenerationException(
                "Failed to generate unique and secure session ID for Redis after " + MAX_COLLISION_RETRIES + " attempts");
    }

    @Override
    @Nullable
    public String getSessionId(HttpServletRequest request) {
        String sessionIdFromAttr = (String) request.getAttribute(TEMP_SESSION_ATTR);
        if (StringUtils.hasText(sessionIdFromAttr)) {
            return sessionIdFromAttr;
        }

        String sessionIdFromCookie = getSessionIdFromCookie(request);
        if (!StringUtils.hasText(sessionIdFromCookie)) {
            return null;
        }

        if (!isValidSessionIdFormat(sessionIdFromCookie)) {
            log.error("Invalid session ID format found in cookie: {}. Discarding.", sessionIdFromCookie);

            return null;
        }

        String redisKey = SESSION_PREFIX + sessionIdFromCookie;
        if (redisTemplate.hasKey(redisKey)) {
            request.setAttribute(TEMP_SESSION_ATTR, sessionIdFromCookie);
            return sessionIdFromCookie;
        }

        return null;
    }

    @Override
    public boolean isSessionIdUnique(String sessionId) {
        if (!StringUtils.hasText(sessionId)) return false;
        String redisKey = SESSION_PREFIX + sessionId;
        return !redisTemplate.hasKey(redisKey);
    }

    @Override
    public String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts) {
        sessionCollisionsResolved.incrementAndGet();
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            String newId = sessionIdGenerator.resolveCollision(originalId, attempt, request);
            if (isSessionIdUnique(newId)) {
                request.setAttribute(TEMP_SESSION_ATTR, newId);
                return newId;
            }
        }
        throw new SessionIdGenerationException(
                "Failed to resolve Redis session ID collision after " + maxAttempts + " attempts for original ID: " + originalId);
    }

    @Override
    public boolean isValidSessionIdFormat(String sessionId) {
        return sessionIdGenerator.isValidFormat(sessionId);
    }

    @Override
    public boolean supportsDistributedSync() {
        return true;
    }

    @Override
    public void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        if (!StringUtils.hasText(sessionId)) return;
        String redisKey = SESSION_PREFIX + sessionId;
        redisTemplate.delete(redisKey);
        request.removeAttribute(TEMP_SESSION_ATTR);
        if (response != null) {
            invalidateSessionCookie(response, request.isSecure());
        }
    }

    @Override
    public void refreshSession(String sessionId) {
        if (!StringUtils.hasText(sessionId)) return;
        String redisKey = SESSION_PREFIX + sessionId;
        Boolean refreshed = redisTemplate.expire(redisKey, sessionTimeout);
        if (!Boolean.TRUE.equals(refreshed)) {
        }
    }

    @Override
    public boolean existsSession(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return false;
        }
        String redisKey = SESSION_PREFIX + sessionId;
        return redisTemplate.hasKey(redisKey);
    }

    @Override
    public void setSessionTimeout(Duration timeout) {
        if (timeout != null && !timeout.isNegative() && !timeout.isZero()) {
            this.sessionTimeout = timeout;
        } else {
            log.error("Invalid session timeout value provided: {}. Retaining current: {}", timeout, this.sessionTimeout);
        }
    }

    @Override
    public String getRepositoryType() {
        return "REDIS";
    }

    private String createSessionValue(String sessionId, HttpServletRequest request) {

        return String.format("user:%s|ip:%s|ua:%s|created:%d",
                request.getRemoteUser() != null ? request.getRemoteUser() : "anonymous",
                getClientIpAddress(request),
                request.getHeader("User-Agent") != null ? request.getHeader("User-Agent").substring(0, Math.min(request.getHeader("User-Agent").length(), 50)) : "unknown",
                System.currentTimeMillis()
        );
    }

    private String getSessionIdFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(cookie -> COOKIE_NAME.equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(StringUtils::hasText)
                .findFirst().orElse(null);
    }

    private void setSessionCookie(HttpServletResponse response, String sessionId, boolean isSecureRequest) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, sessionId)
                .path("/")
                .maxAge(sessionTimeout)
                .httpOnly(true)
                .secure(authContextProperties.isCookieSecure() && isSecureRequest)
                .sameSite("Lax")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void invalidateSessionCookie(HttpServletResponse response, boolean isSecureRequest) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, "")
                .path("/")
                .maxAge(0)
                .httpOnly(true)
                .secure(authContextProperties.isCookieSecure() && isSecureRequest)
                .sameSite("Lax")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            xfHeader = request.getHeader("Proxy-Client-IP");
        }
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            xfHeader = request.getHeader("WL-Proxy-Client-IP");
        }
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            xfHeader = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            xfHeader = request.getRemoteAddr();
        }
        return xfHeader != null ? xfHeader.split(",")[0].trim() : "unknown_ip";
    }

    private void updateSessionStatsAsync() {
        CompletableFuture.runAsync(() -> {
            try {
                redisTemplate.opsForHash().increment(SESSION_STATS_KEY, "totalCreated", 1);
                redisTemplate.opsForHash().increment(SESSION_STATS_KEY, "collisionsResolved", sessionCollisionsResolved.get());
                redisTemplate.opsForHash().put(SESSION_STATS_KEY, "lastUpdate", String.valueOf(Instant.now().toEpochMilli()));
                redisTemplate.expire(SESSION_STATS_KEY, 7, TimeUnit.DAYS);
            } catch (Exception e) {
                log.error("Failed to update session stats in Redis asynchronously", e);
            }
        }).exceptionally(e -> {
            log.error("Async session stat update failed: {}", e.getMessage());
            return null;
        });
    }

    public StringRedisTemplate redisTemplate() {
        return redisTemplate;
    }

    public Duration sessionTimeout() {
        return sessionTimeout;
    }

    public SessionIdGenerator sessionIdGenerator() {
        return sessionIdGenerator;
    }
}