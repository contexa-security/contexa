package io.contexa.contexacore.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.security.async.AsyncSecurityContextProvider;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Slf4j
public class AIReactiveSecurityContextRepository extends HttpSessionSecurityContextRepository {

    @Autowired(required = false) private ZeroTrustSecurityService zeroTrustSecurityService;
    @Autowired(required = false) private SessionIdResolver sessionIdResolver;
    @Autowired(required = false) private RedisTemplate<String, Object> redisTemplate;
    @Autowired(required = false) private AsyncSecurityContextProvider asyncSecurityContextProvider;
    @Autowired private SecurityZeroTrustProperties securityZeroTrustProperties;

    private Cache<String, Boolean> invalidatedSessionsCache;
    private Cache<String, Instant> lastRedisUpdateCache;
    private Cache<String, String> previousAuthCache;

    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public AIReactiveSecurityContextRepository() {
        super();
        this.setAllowSessionCreation(true);
        this.setDisableUrlRewriting(true);
        this.setSpringSecurityContextKey("SPRING_SECURITY_CONTEXT");
    }

    @PostConstruct
    public void initCaches() {
        invalidatedSessionsCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(securityZeroTrustProperties.getCache().getInvalidatedTtlMinutes(), TimeUnit.MINUTES)
                .build();

        lastRedisUpdateCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .build();

        previousAuthCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterAccess(securityZeroTrustProperties.getCache().getSessionTtlMinutes(), TimeUnit.MINUTES)
                .build();
    }

    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        DeferredSecurityContext parentContext = super.loadDeferredContext(request);
        if (!securityZeroTrustProperties.isEnabled()) {
            return parentContext;
        }
        return new ZeroTrustDeferredSecurityContext(parentContext, request);
    }

    private class ZeroTrustDeferredSecurityContext implements DeferredSecurityContext {
        private final DeferredSecurityContext parentContext;
        private final HttpServletRequest request;
        private SecurityContext cachedContext;
        private boolean loaded = false;

        public ZeroTrustDeferredSecurityContext(DeferredSecurityContext parentContext, HttpServletRequest request) {
            this.parentContext = parentContext;
            this.request = request;
        }

        @Override
        public SecurityContext get() {
            if (!loaded) {
                SecurityContext context = parentContext.get();
                Authentication auth = context.getAuthentication();
                String sessionId = extractSessionId(request);

                if (auth != null && trustResolver.isAuthenticated(auth) && zeroTrustSecurityService != null) {
                    String userId = auth.getName();
                    zeroTrustSecurityService.applyZeroTrustToContext(context, userId, sessionId, request);
                }

                cachedContext = context;
                loaded = true;
            }
            return cachedContext;
        }

        @Override
        public boolean isGenerated() {
            return parentContext.isGenerated();
        }
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        String sessionId = extractSessionId(request);
        if (securityZeroTrustProperties.isEnabled() && sessionId != null) {
            Boolean isInvalidated = invalidatedSessionsCache.getIfPresent(sessionId);
            if (isInvalidated != null && isInvalidated) {
                return;
            }

            if (isInvalidated == null && zeroTrustSecurityService != null
                    && zeroTrustSecurityService.isSessionInvalidated(sessionId)) {
                invalidatedSessionsCache.put(sessionId, true);
                return;
            }
        }

        super.saveContext(context, request, response);

        if (securityZeroTrustProperties.isEnabled() && sessionId != null) {
            Authentication auth = context.getAuthentication();

            try {
                if (isActuallyAuthenticated(auth)) {
                    String userId = auth.getName();
                    previousAuthCache.put(sessionId, userId);
                    saveAsyncAuthenticationContext(auth, sessionId);

                    if (securityZeroTrustProperties.getSession().isTrackingEnabled() && shouldUpdateRedis(sessionId)) {
                        trackSessionInRedis(userId, sessionId);
                        lastRedisUpdateCache.put(sessionId, Instant.now());
                    }

                } else if (isLogoutDetected(auth, sessionId)) {
                    String previousUserId = previousAuthCache.getIfPresent(sessionId);
                    if (previousUserId != null) {
                        handleLogout(previousUserId, sessionId);
                        previousAuthCache.invalidate(sessionId);
                    }
                }

            } catch (Exception e) {
                String userId = auth != null ? auth.getName() : "unknown";
                log.error("[ZeroTrust] Error during Zero Trust context update for user: {}", userId, e);
            }
        }
    }

    private boolean isActuallyAuthenticated(Authentication auth) {
        if (auth == null) {
            return false;
        }
        if (auth instanceof AnonymousAuthenticationToken) {
            return false;
        }
        return auth.isAuthenticated() && trustResolver.isAuthenticated(auth);
    }

    private boolean isLogoutDetected(Authentication auth, String sessionId) {
        String previousUserId = previousAuthCache.getIfPresent(sessionId);
        if (previousUserId == null) {
            return false;
        }
        return auth == null || auth instanceof AnonymousAuthenticationToken || !auth.isAuthenticated();
    }

    private boolean shouldUpdateRedis(String sessionId) {
        Instant lastUpdate = lastRedisUpdateCache.getIfPresent(sessionId);
        if (lastUpdate == null) {
            return true;
        }
        return Instant.now().isAfter(lastUpdate.plusSeconds(securityZeroTrustProperties.getRedis().getUpdateIntervalSeconds()));
    }

    private String extractSessionId(HttpServletRequest request) {
        String sessionId = sessionIdResolver != null ? sessionIdResolver.resolve(request) : null;

        if (sessionId == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                sessionId = session.getId();
            }
        }

        return sessionId;
    }

    private void trackSessionInRedis(String userId, String sessionId) {
        if (redisTemplate == null) {
            return;
        }
        try {
            String userSessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().add(userSessionsKey, sessionId);
            redisTemplate.expire(userSessionsKey, Duration.ofDays(7));
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to track session in Redis for user: {}", userId, e);
        }
    }

    private void handleLogout(String userId, String sessionId) {
        try {
            invalidatedSessionsCache.put(sessionId, true);
            lastRedisUpdateCache.invalidate(sessionId);
            removeAsyncAuthenticationContext(userId, sessionId);
            if (zeroTrustSecurityService != null) {
                zeroTrustSecurityService.invalidateSession(sessionId, userId, "User logout");
            }
        } catch (Exception e) {
            log.error("[ZeroTrust] Error handling logout for user: {}", userId, e);
        }
    }

    private void saveAsyncAuthenticationContext(Authentication auth, String sessionId) {
        if (asyncSecurityContextProvider != null) {
            try {
                asyncSecurityContextProvider.saveAuthenticationForAsync(auth, sessionId);
            } catch (Exception e) {
                log.error("[ZeroTrust] Failed to save async authentication context", e);
            }
        }
    }

    private void removeAsyncAuthenticationContext(String userId, String sessionId) {
        if (asyncSecurityContextProvider != null) {
            try {
                asyncSecurityContextProvider.removeAuthentication(userId, sessionId);
            } catch (Exception e) {
                log.error("[ZeroTrust] Failed to remove async authentication context for userId: {}", userId, e);
            }
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
}
