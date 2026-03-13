package io.contexa.contexacore.infra.session.impl;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.SessionIdGenerationException;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@ConditionalOnProperty(name = "security.mfa.session.storage-type", havingValue = "http-session", matchIfMissing = true)
public class HttpSessionMfaRepository implements MfaSessionRepository {

    private static final String MFA_SESSION_ID_ATTRIBUTE = "MFA_SESSION_ID";
    private static final String SESSION_CREATION_TIME_ATTRIBUTE = "MFA_SESSION_CREATION_TIME";

    private final SessionIdGenerator sessionIdGenerator;

    private Duration sessionTimeout = Duration.ofMinutes(30);
    private final AtomicLong totalSessionsCreated = new AtomicLong(0);
    private final AtomicLong sessionCollisions = new AtomicLong(0);
    private final Set<String> activeSessionIds = ConcurrentHashMap.newKeySet();

    public HttpSessionMfaRepository(SessionIdGenerator sessionIdGenerator) {
        this.sessionIdGenerator = sessionIdGenerator;
    }

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        HttpSession session = request.getSession(true);
        session.setAttribute(MFA_SESSION_ID_ATTRIBUTE, sessionId);
        session.setAttribute(SESSION_CREATION_TIME_ATTRIBUTE, System.currentTimeMillis());
        session.setMaxInactiveInterval((int) sessionTimeout.toSeconds());

        activeSessionIds.add(sessionId);
        totalSessionsCreated.incrementAndGet();
            }

    @Override
    @Nullable
    public String getSessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (String) session.getAttribute(MFA_SESSION_ID_ATTRIBUTE);
    }

    @Override
    public void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(MFA_SESSION_ID_ATTRIBUTE);
            session.removeAttribute(SESSION_CREATION_TIME_ATTRIBUTE);
        }
        activeSessionIds.remove(sessionId);
    }

    @Override
    public void refreshSession(String sessionId) {
            }

    @Override
    public boolean existsSession(String sessionId) {
        return sessionId != null && activeSessionIds.contains(sessionId);
    }

    @Override
    public void setSessionTimeout(Duration timeout) {
        this.sessionTimeout = timeout;
            }

    @Override
    public String getRepositoryType() {
        return "HTTP_SESSION";
    }

    @Override
    public String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request) {
        return sessionIdGenerator.generate(baseId, request);
    }

    @Override
    public boolean isSessionIdUnique(String sessionId) {
        return isValidSessionIdFormat(sessionId);
    }

    @Override
    public String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts) {
        sessionCollisions.incrementAndGet();

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            String resolvedId = sessionIdGenerator.resolveCollision(originalId, attempt, request);
            if (isValidSessionIdFormat(resolvedId)) {
                                return resolvedId;
            }
        }

        throw new SessionIdGenerationException(
                "Failed to resolve HTTP session ID collision after " + maxAttempts + " attempts");
    }

    @Override
    public boolean isValidSessionIdFormat(String sessionId) {
        return sessionIdGenerator.isValidFormat(sessionId);
    }

    @Override
    public boolean supportsDistributedSync() {
        return false;
    }
}