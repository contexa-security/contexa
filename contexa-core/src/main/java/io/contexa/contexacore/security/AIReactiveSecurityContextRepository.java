package io.contexa.contexacore.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.security.async.AsyncSecurityContextProvider;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
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
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Slf4j
public class AIReactiveSecurityContextRepository extends HttpSessionSecurityContextRepository {

    @Autowired private ZeroTrustSecurityService zeroTrustSecurityService;
    @Autowired private SessionIdResolver sessionIdResolver;
    @Autowired private RedisTemplate<String, Object> redisTemplate;
    @Autowired private AsyncSecurityContextProvider asyncSecurityContextProvider;
    @Autowired private SecurityZeroTrustProperties securityZeroTrustProperties;
    private Cache<String, Boolean> invalidatedSessionsCache;
    private Cache<String, Set<String>> userSessionsCache;
    private Cache<String, String> sessionToUserCache;
    private Cache<String, Instant> lastRedisUpdateCache;
    private Cache<String, String> previousAuthCache;
    private ScheduledExecutorService cacheCleanupScheduler;

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

        userSessionsCache = Caffeine.newBuilder()
                .maximumSize(5000)
                .expireAfterAccess(securityZeroTrustProperties.getCache().getSessionTtlMinutes(), TimeUnit.MINUTES)
                .build();

        sessionToUserCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterAccess(securityZeroTrustProperties.getCache().getSessionTtlMinutes(), TimeUnit.MINUTES)
                .build();

        lastRedisUpdateCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .build();

        previousAuthCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterAccess(securityZeroTrustProperties.getCache().getSessionTtlMinutes(), TimeUnit.MINUTES)
                .build();

        cacheCleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ZeroTrust-Cache-Monitor");
            t.setDaemon(true);
            return t;
        });

        cacheCleanupScheduler.scheduleAtFixedRate(this::logCacheStats, 5, 5, TimeUnit.MINUTES);

    }

    @PreDestroy
    public void destroyCaches() {
        if (cacheCleanupScheduler != null && !cacheCleanupScheduler.isShutdown()) {
            cacheCleanupScheduler.shutdown();
            try {
                if (!cacheCleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    cacheCleanupScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                cacheCleanupScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    private void logCacheStats() {
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

                if (auth != null && trustResolver.isAuthenticated(auth)) {

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

            if (isInvalidated == null && zeroTrustSecurityService.isSessionInvalidated(sessionId)) {
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
                        updateUserSessionMapping(userId, sessionId);
                        updateUserContext(userId, sessionId, request);
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
                log.error("[ZeroTrust] Error during Zero Trust metrics update for user: {}", userId, e);
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

        String sessionId = sessionIdResolver.resolve(request);

        if (sessionId == null) {

            HttpSession session = request.getSession(false);
            if (session != null) {
                sessionId = session.getId();
            }
        }

        return sessionId;
    }

    private void trackLocalSession(String userId, String sessionId) {

        Set<String> sessions = userSessionsCache.get(userId, k -> ConcurrentHashMap.newKeySet());
        sessions.add(sessionId);
        sessionToUserCache.put(sessionId, userId);
    }

    private void updateUserSessionMapping(String userId, String sessionId) {
        try {
            trackLocalSession(userId, sessionId);
            String mappingKey = ZeroTrustRedisKeys.sessionUser(sessionId);
            redisTemplate.opsForValue().set(mappingKey, userId, Duration.ofHours(24));

            String userSessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().add(userSessionsKey, sessionId);
            redisTemplate.expire(userSessionsKey, Duration.ofDays(7));

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to update user session mapping", e);
        }
    }

    private void updateUserContext(String userId, String sessionId, HttpServletRequest request) {
        try {
            String userContextKey = ZeroTrustRedisKeys.userContext(userId);
            UserSecurityContext userContext = (UserSecurityContext) redisTemplate.opsForValue().get(userContextKey);

            if (userContext == null) {
                userContext = UserSecurityContext.builder()
                        .userId(userId)
                        .currentThreatScore(zeroTrustSecurityService.getThreatScore(userId))
                        .createdAt(java.time.LocalDateTime.now())
                        .build();
            }

            UserSecurityContext.SessionContext sessionContext = UserSecurityContext.SessionContext.builder()
                    .sessionId(sessionId)
                    .lastAccessTime(java.time.LocalDateTime.now())
                    .active(true)
                    .build();

            userContext.addSession(sessionContext);
            userContext.setUpdatedAt(java.time.LocalDateTime.now());

            redisTemplate.opsForValue().set(userContextKey, userContext, Duration.ofDays(30));

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to update user context for user: {}", userId, e);
        }
    }

    private void handleLogout(String userId, String sessionId) {
        try {
            sessionToUserCache.invalidate(sessionId);
            Set<String> sessions = userSessionsCache.getIfPresent(userId);
            if (sessions != null) {
                sessions.remove(sessionId);
                if (sessions.isEmpty()) {
                    userSessionsCache.invalidate(userId);
                }
            }
            invalidatedSessionsCache.put(sessionId, true);
            lastRedisUpdateCache.invalidate(sessionId);
            removeAsyncAuthenticationContext(userId, sessionId);
            zeroTrustSecurityService.invalidateSession(sessionId, userId, "User logout");

        } catch (Exception e) {
            log.error("[ZeroTrust] Error handling logout for user: {}", userId, e);
        }
    }

    private void saveAsyncAuthenticationContext(Authentication auth, String sessionId) {
        if (asyncSecurityContextProvider != null) {
            try {
                asyncSecurityContextProvider.saveAuthenticationForAsync(auth, sessionId);
            } catch (Exception e) {
                log.error("[ZeroTrust] Failed to save async authentication context for sessionId: {}", maskSessionId(sessionId), e);
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

    private String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 8) {
            return "***";
        }
        return sessionId.substring(0, 4) + "..." + sessionId.substring(sessionId.length() - 4);
    }

    @Override
    public void setAllowSessionCreation(boolean allowSessionCreation) {
        super.setAllowSessionCreation(allowSessionCreation);
    }

    public void invalidateAllUserSessions(String userId, String reason) {
        if (!securityZeroTrustProperties.isEnabled()) {
            return;
        }

        try {
            log.error("[ZeroTrust] Invalidating all sessions for user: {} - Reason: {}", userId, reason);

            Set<String> userSessions = userSessionsCache.getIfPresent(userId);
            if (userSessions != null) {
                for (String sessionId : new HashSet<>(userSessions)) {
                    invalidatedSessionsCache.put(sessionId, true);
                    sessionToUserCache.invalidate(sessionId);
                    lastRedisUpdateCache.invalidate(sessionId);
                    previousAuthCache.invalidate(sessionId);
                }
                userSessionsCache.invalidate(userId);
            }
            zeroTrustSecurityService.invalidateAllUserSessions(userId, reason);

        } catch (Exception e) {
            log.error("[ZeroTrust] Error invalidating all sessions for user: {}", userId, e);
        }
    }
}