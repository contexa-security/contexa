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
package io.contexa.contexacore.infra.session.impl;

import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.SessionIdGenerationException;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * MFA sessions kept in the user's HTTP session. Z-16 (F5): as in RedisMfaRepository, an MFA session lasts its timeout
 * from its creation or its last MFA event ({@link #refreshSession}), whatever other requests come, and storing it
 * leaves the idle limit of the HTTP session alone. The sessions in force are an {@link ExpiringKeySpace} (Z-16, N-1).
 */
@Slf4j
@ConditionalOnProperty(name = "contexa.auth.mfa.session-storage-type", havingValue = "http-session", matchIfMissing = true)
public class HttpSessionMfaRepository implements MfaSessionRepository {

    private static final String MFA_SESSION_ID_ATTRIBUTE = "MFA_SESSION_ID";
    private static final String SESSION_CREATION_TIME_ATTRIBUTE = "MFA_SESSION_CREATION_TIME";

    private final SessionIdGenerator sessionIdGenerator;

    private Duration sessionTimeout = Duration.ofMinutes(30);
    private final AtomicLong totalSessionsCreated = new AtomicLong(0);
    private final AtomicLong sessionCollisions = new AtomicLong(0);
    /** Each MFA session in force, until it lapses without another MFA event. */
    private final ExpiringKeySpace<Boolean> activeSessions =
            ExpiringKeySpace.<Boolean>builder(Clock.systemUTC()).build();

    public HttpSessionMfaRepository(SessionIdGenerator sessionIdGenerator) {
        this.sessionIdGenerator = sessionIdGenerator;
    }

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        HttpSession session = request.getSession(true);
        session.setAttribute(MFA_SESSION_ID_ATTRIBUTE, sessionId);
        session.setAttribute(SESSION_CREATION_TIME_ATTRIBUTE, System.currentTimeMillis());

        activeSessions.put(sessionId, Boolean.TRUE, sessionTimeout);
        totalSessionsCreated.incrementAndGet();
            }

    @Override
    @Nullable
    public String getSessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        String sessionId = (String) session.getAttribute(MFA_SESSION_ID_ATTRIBUTE);
        return sessionId != null && existsSession(sessionId) ? sessionId : null;
    }

    @Override
    public void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(MFA_SESSION_ID_ATTRIBUTE);
            session.removeAttribute(SESSION_CREATION_TIME_ATTRIBUTE);
        }
        if (sessionId != null) {
            activeSessions.remove(sessionId);
        }
    }

    /** Keeps an MFA session in force another timeout, as the Redis repository extends its key. */
    @Override
    public void refreshSession(String sessionId) {
        if (sessionId == null) {
            return;
        }
        activeSessions.getAndRefresh(sessionId, sessionTimeout);
    }

    @Override
    @Nullable
    public String sessionIdOf(HttpSession session) {
        return session == null ? null : (String) session.getAttribute(MFA_SESSION_ID_ATTRIBUTE);
    }

    @Override
    public void forgetSession(String sessionId) {
        if (sessionId != null) {
            activeSessions.remove(sessionId);
        }
    }

    /** Whether the MFA session is in force; one past its timeout is gone, as its Redis key is. */
    @Override
    public boolean existsSession(String sessionId) {
        if (sessionId == null) {
            return false;
        }
        return activeSessions.containsKey(sessionId);
    }

    @Override
    public void setSessionTimeout(Duration timeout) {
        if (timeout != null && !timeout.isNegative() && !timeout.isZero()) {
            this.sessionTimeout = timeout;
        } else {
            log.error("Invalid session timeout value provided: {}. Retaining current: {}",
                    timeout, this.sessionTimeout);
        }
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
        return isValidSessionIdFormat(sessionId) && !existsSession(sessionId);
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