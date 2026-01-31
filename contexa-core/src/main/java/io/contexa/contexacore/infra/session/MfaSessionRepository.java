package io.contexa.contexacore.infra.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;

import java.time.Duration;

public interface MfaSessionRepository {

    void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    @Nullable
    String getSessionId(HttpServletRequest request);

    void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    void refreshSession(String sessionId);

    boolean existsSession(String sessionId);

    void setSessionTimeout(Duration timeout);

    String getRepositoryType();

    String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request);

    boolean isSessionIdUnique(String sessionId);

    String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts);

    boolean isValidSessionIdFormat(String sessionId);

    boolean supportsDistributedSync();
}