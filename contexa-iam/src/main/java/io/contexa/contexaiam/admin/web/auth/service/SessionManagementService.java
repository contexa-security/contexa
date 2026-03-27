package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexaiam.domain.entity.ActiveSession;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Manages active session tracking, querying, and forced invalidation.
 */
@Slf4j
@RequiredArgsConstructor
public class SessionManagementService {

    private static final long UPDATE_THRESHOLD_SECONDS = 60;
    private static final int CLEANUP_RETENTION_DAYS = 7;

    private final ActiveSessionRepository activeSessionRepository;

    @Transactional(readOnly = true)
    public Page<ActiveSession> getActiveSessions(Pageable pageable) {
        return activeSessionRepository.findByExpiredFalse(pageable);
    }

    @Transactional(readOnly = true)
    public List<ActiveSession> getSessionsByUser(String userId) {
        return activeSessionRepository.findByUserIdAndExpiredFalse(userId);
    }

    @Transactional(readOnly = true)
    public long getActiveSessionCount() {
        return activeSessionRepository.countByExpiredFalse();
    }

    @Transactional
    public void invalidateSession(String sessionId) {
        activeSessionRepository.expireSession(sessionId);
    }

    @Transactional
    public void invalidateAllSessionsForUser(String userId) {
        activeSessionRepository.expireAllSessionsForUser(userId);
    }

    /**
     * Track or update a session record.
     * Only updates last_accessed_at if the threshold (60s) has passed to reduce DB overhead.
     */
    @Transactional
    public void trackSession(String sessionId, String userId, String username,
                             String clientIp, String userAgent) {
        activeSessionRepository.findById(sessionId).ifPresentOrElse(
                existing -> {
                    if (!existing.isExpired() && shouldUpdateLastAccess(existing.getLastAccessedAt())) {
                        existing.setLastAccessedAt(LocalDateTime.now());
                        activeSessionRepository.save(existing);
                    }
                },
                () -> {
                    LocalDateTime now = LocalDateTime.now();
                    ActiveSession session = ActiveSession.builder()
                            .sessionId(sessionId)
                            .userId(userId)
                            .username(username)
                            .clientIp(clientIp)
                            .userAgent(truncate(userAgent, 512))
                            .createdAt(now)
                            .lastAccessedAt(now)
                            .expired(false)
                            .build();
                    activeSessionRepository.save(session);
                }
        );
    }

    @Transactional
    public void updateLastAccessed(String sessionId) {
        activeSessionRepository.findById(sessionId).ifPresent(session -> {
            if (!session.isExpired()) {
                session.setLastAccessedAt(LocalDateTime.now());
                activeSessionRepository.save(session);
            }
        });
    }

    @Transactional
    public void markExpired(String sessionId) {
        activeSessionRepository.expireSession(sessionId);
    }

    /**
     * Delete expired sessions older than 7 days.
     */
    @Transactional
    public void cleanupExpiredSessions() {
        LocalDateTime threshold = LocalDateTime.now().minusDays(CLEANUP_RETENTION_DAYS);
        activeSessionRepository.deleteExpiredBefore(threshold);
    }

    @Transactional(readOnly = true)
    public List<ActiveSession> getAllActiveSessions() {
        return activeSessionRepository.findByExpiredFalseOrderByLastAccessedAtDesc();
    }

    private boolean shouldUpdateLastAccess(LocalDateTime lastAccessedAt) {
        if (lastAccessedAt == null) {
            return true;
        }
        return lastAccessedAt.plusSeconds(UPDATE_THRESHOLD_SECONDS).isBefore(LocalDateTime.now());
    }

    private String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        return value.length() > maxLength ? value.substring(0, maxLength) : value;
    }
}
