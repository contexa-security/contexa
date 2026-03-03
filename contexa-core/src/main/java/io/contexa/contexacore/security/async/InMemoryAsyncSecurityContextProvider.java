package io.contexa.contexacore.security.async;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Optional;

@Slf4j
public class InMemoryAsyncSecurityContextProvider extends AbstractAsyncSecurityContextProvider {

    private final Cache<String, AsyncAuthenticationData> userStore;
    private final Cache<String, AsyncAuthenticationData> compositeStore;
    private final Cache<String, String> sessionToUserStore;

    public InMemoryAsyncSecurityContextProvider() {
        this.userStore = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(DEFAULT_TTL)
                .build();
        this.compositeStore = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(DEFAULT_TTL)
                .build();
        this.sessionToUserStore = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(DEFAULT_TTL)
                .build();
    }

    @Override
    protected void doSave(String userId, String sessionId, AsyncAuthenticationData data) {
        userStore.put(userId, data);

        if (sessionId != null) {
            compositeStore.put(userId + ":" + sessionId, data);
            sessionToUserStore.put(sessionId, userId);
        }
    }

    @Override
    public Optional<AsyncAuthenticationData> getAuthenticationByUserId(String userId) {
        if (userId == null || userId.isEmpty()) {
            return Optional.empty();
        }

        AsyncAuthenticationData data = userStore.getIfPresent(userId);
        if (data != null && data.isValid()) {
            return Optional.of(data);
        }
        return Optional.empty();
    }

    @Override
    public Optional<AsyncAuthenticationData> getAuthenticationBySessionId(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            return Optional.empty();
        }

        String userId = sessionToUserStore.getIfPresent(sessionId);
        if (userId != null) {
            AsyncAuthenticationData data = compositeStore.getIfPresent(userId + ":" + sessionId);
            if (data != null && data.isValid()) {
                return Optional.of(data);
            }
            return getAuthenticationByUserId(userId);
        }
        return Optional.empty();
    }

    @Override
    public void removeAuthentication(String userId, String sessionId) {
        if (userId != null) {
            userStore.invalidate(userId);
        }
        if (userId != null && sessionId != null) {
            compositeStore.invalidate(userId + ":" + sessionId);
        }
        if (sessionId != null) {
            sessionToUserStore.invalidate(sessionId);
        }
    }

    @Override
    public void refreshExpiration(String userId, String sessionId) {
        if (userId == null) {
            return;
        }

        AsyncAuthenticationData data = userStore.getIfPresent(userId);
        if (data != null) {
            data.setExpiresAt(Instant.now().plus(DEFAULT_TTL));
            userStore.put(userId, data);
        }
    }
}
