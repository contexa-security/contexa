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

import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.function.Supplier;
import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexaiam.domain.entity.ActiveSession;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.lang.Nullable;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Manages active session tracking, querying, and forced invalidation. A session is kept, shown and invalidated by its
 * reference ({@link RequestFactRedaction#sessionReference}), the value the audit names it by: the value its cookie
 * carries is never kept, so no one who reads the console or the database can take the session. An identifier handed
 * over raw is turned into its reference here; a reference stays as it is.
 *
 * <p>Ending a session also ends what keeps its person in beyond the tracked row ({@link IForceLogoutService}, as a changed
 * password or a disabled account does): the HTTP session is not all of it; the access token works until it expires and
 * the refresh token brings new ones. The tokens are not tied to one HTTP session, so ending one session ends every
 * sign-in of its person.</p>
 */
@Slf4j
public class SessionManagementService {

    private static final long UPDATE_THRESHOLD_SECONDS = 60;
    private static final int CLEANUP_RETENTION_DAYS = 7;

    private final ActiveSessionRepository activeSessionRepository;
    private final ActiveSessionReferences references;
    private static final String FORCE_LOGOUT_REASON = "CONSOLE_SESSION_INVALIDATED";

    private final Supplier<IForceLogoutService> forceLogout;

    public SessionManagementService(ActiveSessionRepository activeSessionRepository) {
        this(activeSessionRepository, null);
    }

    public SessionManagementService(ActiveSessionRepository activeSessionRepository,
                                    @Nullable ActiveSessionReferences references) {
        this(activeSessionRepository, references, null);
    }

    /**
     * @param references  turns the rows a node not yet on references wrote into their references when the console reads
     *                    the sessions, or null to leave them to the next start
     * @param forceLogout gives the forced logout that ends the person's sessions and sign-in tokens, or null (or a supplier
     *                    of null) where the application keeps its people in HTTP sessions only
     */
    public SessionManagementService(ActiveSessionRepository activeSessionRepository,
                                    @Nullable ActiveSessionReferences references,
                                    @Nullable Supplier<IForceLogoutService> forceLogout) {
        this.activeSessionRepository = activeSessionRepository;
        this.references = references;
        this.forceLogout = forceLogout != null ? forceLogout : () -> null;
    }

    /**
     * Turns the tracked sessions that a node not yet on references wrote under the value their cookie carries into
     * their references, so that what the console lists, exports and ends is what is stored. Call it before reading the
     * sessions, outside the transaction of the read: it writes, and a read-only transaction does not.
     *
     * @return how many tracked sessions were turned into their references
     */
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
    public int referenceRawSessions() {
        return references != null ? references.whenRead() : 0;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<ActiveSession> getActiveSessions(Pageable pageable) {
        return activeSessionRepository.findByExpiredFalse(pageable);
    }
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<ActiveSession> searchActiveSessions(String keyword, Pageable pageable) {
        if (StringUtils.hasText(keyword)) {
            String likePattern = "%" + keyword.trim().toLowerCase(Locale.ROOT) + "%";
            return activeSessionRepository.searchActiveSessions(likePattern, pageable);
        }
        return getActiveSessions(pageable);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<ActiveSession> getSessionsByUser(String userId) {
        return activeSessionRepository.findByUserIdAndExpiredFalse(userId);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public long getActiveSessionCount() {
        return activeSessionRepository.countByExpiredFalse();
    }

    /**
     * Ends the session and every sign-in of its person.
     *
     * @return whether the person's sign-ins were ended as well; false where only the HTTP sessions keep people in
     * @throws NoSuchElementException when no tracked session has that identifier
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public boolean invalidateSession(String sessionId) {
        String reference = RequestFactRedaction.sessionReference(sessionId);
        ActiveSession session = activeSessionRepository.findById(reference)
                .orElseThrow(() -> new NoSuchElementException("Session not found: " + sessionId));
        activeSessionRepository.expireSession(reference);
        return endSignIns(session.getUserId());
    }

    /**
     * Ends every tracked session of the person and every sign-in of the person, also those the console never tracked.
     *
     * @return whether the person's sign-ins were ended as well; false where only the HTTP sessions keep people in
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public boolean invalidateAllSessionsForUser(String userId) {
        activeSessionRepository.expireAllSessionsForUser(userId);
        return endSignIns(userId);
    }

    private boolean endSignIns(String userId) {
        IForceLogoutService logout = forceLogout.get();
        if (logout == null || !StringUtils.hasText(userId)) {
            return false;
        }
        logout.forceLogoutByUserId(userId, FORCE_LOGOUT_REASON);
        log.info("[SessionManagement] Ended the sign-ins of a person from the console: userId={}", userId);
        return true;
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
                RequestFactRedaction.sessionReference(sessionId),
                userId,
                username,
                clientIp,
                truncate(userAgent, 512),
                now,
                now.minusSeconds(UPDATE_THRESHOLD_SECONDS));
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void updateLastAccessed(String sessionId) {
        activeSessionRepository.findById(RequestFactRedaction.sessionReference(sessionId)).ifPresent(session -> {
            if (!session.isExpired()) {
                session.setLastAccessedAt(LocalDateTime.now());
                activeSessionRepository.save(session);
            }
        });
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void markExpired(String sessionId) {
        activeSessionRepository.expireSession(RequestFactRedaction.sessionReference(sessionId));
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

    private String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        return value.length() > maxLength ? value.substring(0, maxLength) : value;
    }
}
