package io.contexa.contexacore.security.async;

import org.springframework.security.core.Authentication;

import java.util.Optional;

public interface AsyncSecurityContextProvider {

    void saveAuthenticationForAsync(Authentication auth, String sessionId);

    Optional<AsyncAuthenticationData> getAuthenticationByUserId(String userId);

    Optional<AsyncAuthenticationData> getAuthenticationBySessionId(String sessionId);

    Optional<AsyncAuthenticationData> getCurrentAuthentication(String fallbackUserId);

    void removeAuthentication(String userId, String sessionId);

    void refreshExpiration(String userId, String sessionId);
}
