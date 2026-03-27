package io.contexa.contexacore.security.async;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
public abstract class AbstractAsyncSecurityContextProvider implements AsyncSecurityContextProvider {

    protected static final Duration DEFAULT_TTL = Duration.ofHours(24);

    @Override
    public void saveAuthenticationForAsync(Authentication auth, String sessionId) {
        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        String userId = auth.getName();
        if (userId == null || "anonymousUser".equals(userId)) {
            return;
        }

        try {
            Instant now = Instant.now();
            AsyncAuthenticationData data = AsyncAuthenticationData.builder()
                    .userId(userId)
                    .sessionId(sessionId)
                    .principalType(auth.getPrincipal() != null
                            ? auth.getPrincipal().getClass().getSimpleName()
                            : "Unknown")
                    .authorities(auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList()))
                    .createdAt(now)
                    .expiresAt(now.plus(DEFAULT_TTL))
                    .build();

            doSave(userId, sessionId, data);
        } catch (Exception e) {
            log.error("Failed to save authentication for async context - userId: {}", userId, e);
        }
    }

    @Override
    public Optional<AsyncAuthenticationData> getCurrentAuthentication(String fallbackUserId) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                return resolveByUserId(auth.getName());
            }
        } catch (Exception e) {
            log.error("Failed to get current authentication", e);
        }

        if (fallbackUserId != null) {
            return resolveByUserId(fallbackUserId);
        }

        return Optional.empty();
    }

    protected Optional<AsyncAuthenticationData> resolveByUserId(String userId) {
        return getAuthenticationByUserId(userId);
    }

    protected abstract void doSave(String userId, String sessionId, AsyncAuthenticationData data);
}
