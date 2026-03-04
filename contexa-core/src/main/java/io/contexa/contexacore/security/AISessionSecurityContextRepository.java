package io.contexa.contexacore.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.async.AsyncSecurityContextProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * Session-based SecurityContextRepository with Zero Trust integration.
 * Applies Zero Trust verification during DeferredSecurityContext loading
 * for session-managed authentication flows (Form Login, MFA, etc.).
 *
 * @see AISecurityContextSupport
 * @see AIOAuth2SecurityContextRepository
 */
@Slf4j
public class AISessionSecurityContextRepository extends HttpSessionSecurityContextRepository
        implements AISecurityContextRepository {

    private final AISecurityContextSupport support;
    private final SecurityContextDataStore securityContextDataStore;
    private final AsyncSecurityContextProvider asyncSecurityContextProvider;

    private final Cache<String, Boolean> invalidatedSessionsCache;
    private final Cache<String, Instant> lastRedisUpdateCache;
    private final Cache<String, String> previousAuthCache;

    public AISessionSecurityContextRepository(
            AISecurityContextSupport support,
            @Nullable SecurityContextDataStore securityContextDataStore,
            @Nullable AsyncSecurityContextProvider asyncSecurityContextProvider) {
        super();
        this.support = support;
        this.securityContextDataStore = securityContextDataStore;
        this.asyncSecurityContextProvider = asyncSecurityContextProvider;
        this.setAllowSessionCreation(true);
        this.setDisableUrlRewriting(true);
        this.setSpringSecurityContextKey("SPRING_SECURITY_CONTEXT");

        SecurityZeroTrustProperties properties = support.getProperties();
        this.invalidatedSessionsCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(properties.getCache().getInvalidatedTtlMinutes(), TimeUnit.MINUTES)
                .build();

        this.lastRedisUpdateCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .build();

        this.previousAuthCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterAccess(properties.getCache().getSessionTtlMinutes(), TimeUnit.MINUTES)
                .build();
    }

    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        DeferredSecurityContext parentContext = super.loadDeferredContext(request);
        if (!support.isEnabled()) {
            return parentContext;
        }
        return new ZeroTrustDeferredSecurityContext(parentContext, request);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        String sessionId = support.resolveIdentifier(request, context.getAuthentication());
        if (support.isEnabled() && sessionId != null) {
            Boolean isInvalidated = invalidatedSessionsCache.getIfPresent(sessionId);
            if (isInvalidated != null && isInvalidated) {
                return;
            }

            if (isInvalidated == null && support.isSessionInvalidated(sessionId)) {
                invalidatedSessionsCache.put(sessionId, true);
                return;
            }
        }

        super.saveContext(context, request, response);

        if (support.isEnabled() && sessionId != null) {
            Authentication auth = context.getAuthentication();

            try {
                if (support.isActuallyAuthenticated(auth)) {
                    String userId = auth.getName();
                    previousAuthCache.put(sessionId, userId);
                    saveAsyncAuthenticationContext(auth, sessionId);

                    if (support.getProperties().getSession().isTrackingEnabled() && shouldUpdateRedis(sessionId)) {
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

    @Override
    public void invalidateAllUserSessions(String userId, String reason) {
        support.invalidateAllUserSessions(userId, reason);
    }

    private boolean isLogoutDetected(Authentication auth, String sessionId) {
        String previousUserId = previousAuthCache.getIfPresent(sessionId);
        if (previousUserId == null) {
            return false;
        }
        return !support.isActuallyAuthenticated(auth);
    }

    private boolean shouldUpdateRedis(String sessionId) {
        Instant lastUpdate = lastRedisUpdateCache.getIfPresent(sessionId);
        if (lastUpdate == null) {
            return true;
        }
        return Instant.now().isAfter(lastUpdate.plusSeconds(support.getProperties().getRedis().getUpdateIntervalSeconds()));
    }

    private void trackSessionInRedis(String userId, String sessionId) {
        if (securityContextDataStore == null) {
            return;
        }
        securityContextDataStore.trackUserSession(userId, sessionId);
    }

    private void handleLogout(String userId, String sessionId) {
        try {
            invalidatedSessionsCache.put(sessionId, true);
            lastRedisUpdateCache.invalidate(sessionId);
            removeAsyncAuthenticationContext(userId, sessionId);
            support.invalidateSession(sessionId, userId, "User logout");
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
                String identifier = support.resolveIdentifier(request, auth);

                if (auth != null && support.getTrustResolver().isAuthenticated(auth)) {
                    String userId = auth.getName();
                    support.applyZeroTrust(context, userId, identifier, request);
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
}
