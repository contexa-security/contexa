package io.contexa.contexacore.infra.session.impl;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.SessionIdGenerationException;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * InMemory 기반 MFA 세션 Repository - 개발/테스트 환경 최적화
 */
@Slf4j
@ConditionalOnProperty(name = "security.mfa.session.storage-type", havingValue = "memory")
public class InMemoryMfaRepository implements MfaSessionRepository {

    private final ConcurrentHashMap<String, SessionEntry> sessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor();

    private final SessionIdGenerator sessionIdGenerator;

    private Duration sessionTimeout = Duration.ofMinutes(30);
    private final AtomicLong totalSessionsCreated = new AtomicLong(0);
    private final AtomicLong sessionCollisions = new AtomicLong(0);

    public InMemoryMfaRepository(SessionIdGenerator sessionIdGenerator) {
        this.sessionIdGenerator = sessionIdGenerator;
    }

    @jakarta.annotation.PostConstruct
    public void init() {
        cleanupExecutor.scheduleAtFixedRate(this::cleanupExpiredSessions, 5, 5, TimeUnit.MINUTES);
    }

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        SessionEntry entry = new SessionEntry(sessionId, Instant.now().plus(sessionTimeout));

        if (sessions.putIfAbsent(sessionId, entry) != null) {
            sessionCollisions.incrementAndGet();
            throw new SessionIdGenerationException("Session ID already exists in memory: " + sessionId);
        }

        totalSessionsCreated.incrementAndGet();
        log.debug("MFA session stored in memory: {}", sessionId);
    }

    @Override
    @Nullable
    public String getSessionId(HttpServletRequest request) {
        return (String) request.getAttribute("MFA_SESSION_ID");
    }

    @Override
    public void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        sessions.remove(sessionId);
        log.debug("MFA session removed from memory: {}", sessionId);
    }

    @Override
    public void refreshSession(String sessionId) {
        SessionEntry entry = sessions.get(sessionId);
        if (entry != null) {
            entry.expiryTime = Instant.now().plus(sessionTimeout);
            log.trace("Memory session refreshed for: {}", sessionId);
        }
    }

    @Override
    public boolean existsSession(String sessionId) {
        SessionEntry entry = sessions.get(sessionId);
        if (entry == null) {
            return false;
        }

        if (entry.isExpired()) {
            sessions.remove(sessionId);
            return false;
        }

        return true;
    }

    @Override
    public void setSessionTimeout(Duration timeout) {
        this.sessionTimeout = timeout;
        log.info("Memory session timeout set to: {}", timeout);
    }

    @Override
    public String getRepositoryType() {
        return "IN_MEMORY";
    }

    @Override
    public String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request) {
        for (int attempt = 0; attempt < 10; attempt++) {
            String sessionId = sessionIdGenerator.generate(baseId, request);

            if (isSessionIdUnique(sessionId)) {
                return sessionId;
            }

            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        throw new SessionIdGenerationException("Failed to generate unique session ID for memory storage");
    }

    @Override
    public boolean isSessionIdUnique(String sessionId) {
        return !sessions.containsKey(sessionId);
    }

    @Override
    public String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts) {
        sessionCollisions.incrementAndGet();

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            String resolvedId = sessionIdGenerator.resolveCollision(originalId, attempt, request);
            if (isSessionIdUnique(resolvedId)) {
                return resolvedId;
            }
        }

        throw new SessionIdGenerationException("Failed to resolve memory session ID collision");
    }

    @Override
    public boolean isValidSessionIdFormat(String sessionId) {
        return sessionIdGenerator.isValidFormat(sessionId);
    }

    @Override
    public boolean supportsDistributedSync() {
        return false;
    }

    @Override
    public SessionStats getSessionStats() {
        cleanupExpiredSessions();

        return new SessionStats(
                sessions.size(),
                totalSessionsCreated.get(),
                sessionCollisions.get(),
                sessionTimeout.toSeconds() * 0.7,
                getRepositoryType()
        );
    }

    private void cleanupExpiredSessions() {
        Instant now = Instant.now();
        int removed = 0;

        var iterator = sessions.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (entry.getValue().expiryTime.isBefore(now)) {
                iterator.remove();
                removed++;
            }
        }

        if (removed > 0) {
            log.debug("Cleaned up {} expired sessions from memory", removed);
        }
    }

    private static class SessionEntry {
        final String sessionId;
        volatile Instant expiryTime;

        SessionEntry(String sessionId, Instant expiryTime) {
            this.sessionId = sessionId;
            this.expiryTime = expiryTime;
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiryTime);
        }
    }
}