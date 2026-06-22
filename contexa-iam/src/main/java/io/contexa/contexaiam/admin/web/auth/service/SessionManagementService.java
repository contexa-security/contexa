/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<ActiveSession> getActiveSessions(Pageable pageable) {
        return activeSessionRepository.findByExpiredFalse(pageable);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<ActiveSession> getSessionsByUser(String userId) {
        return activeSessionRepository.findByUserIdAndExpiredFalse(userId);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public long getActiveSessionCount() {
        return activeSessionRepository.countByExpiredFalse();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void invalidateSession(String sessionId) {
        activeSessionRepository.expireSession(sessionId);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void invalidateAllSessionsForUser(String userId) {
        activeSessionRepository.expireAllSessionsForUser(userId);
    }

    /**
     * Track or update a session record.
     * Only updates last_accessed_at if the threshold (60s) has passed to reduce DB overhead.
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public void trackSession(String sessionId, String userId, String username,
                             String clientIp, String userAgent) {
        LocalDateTime now = LocalDateTime.now();
        activeSessionRepository.upsertSession(
                sessionId,
                userId,
                username,
                clientIp,
                truncate(userAgent, 512),
                now,
                now.minusSeconds(UPDATE_THRESHOLD_SECONDS));
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void updateLastAccessed(String sessionId) {
        activeSessionRepository.findById(sessionId).ifPresent(session -> {
            if (!session.isExpired()) {
                session.setLastAccessedAt(LocalDateTime.now());
                activeSessionRepository.save(session);
            }
        });
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void markExpired(String sessionId) {
        activeSessionRepository.expireSession(sessionId);
    }

    /**
     * Delete expired sessions older than 7 days.
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public void cleanupExpiredSessions() {
        LocalDateTime threshold = LocalDateTime.now().minusDays(CLEANUP_RETENTION_DAYS);
        activeSessionRepository.deleteExpiredBefore(threshold);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
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
