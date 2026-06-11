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
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryZeroTrustSecurityService extends AbstractZeroTrustSecurityService {

    private static final Duration DEFAULT_INVALIDATION_TTL = Duration.ofHours(24);

    private final ConcurrentHashMap<String, Instant> invalidatedSessionExpiry = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> userSessions = new ConcurrentHashMap<>();
    private final Duration invalidationTtl;
    private final Clock clock;

    public InMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster) {
        this(threatScoreUtil, securityZeroTrustProperties, actionRepository,
                blockingSignalBroadcaster, DEFAULT_INVALIDATION_TTL, Clock.systemUTC());
    }

    public InMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            Duration invalidationTtl) {
        this(threatScoreUtil, securityZeroTrustProperties, actionRepository,
                blockingSignalBroadcaster, invalidationTtl, Clock.systemUTC());
    }

    public InMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            Duration invalidationTtl,
            Clock clock) {
        super(threatScoreUtil, securityZeroTrustProperties, actionRepository);
        this.blockingSignalBroadcaster = blockingSignalBroadcaster;
        this.invalidationTtl = Objects.requireNonNull(invalidationTtl, "invalidationTtl");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public void invalidateSession(String sessionId, String userId, String reason) {
        if (sessionId == null) {
            return;
        }
        invalidatedSessionExpiry.put(sessionId, clock.instant().plus(invalidationTtl));
    }

    @Override
    public boolean isSessionInvalidated(String sessionId) {
        if (sessionId == null) {
            return false;
        }
        Instant expiresAt = invalidatedSessionExpiry.get(sessionId);
        if (expiresAt == null) {
            return false;
        }
        if (clock.instant().isAfter(expiresAt)) {
            invalidatedSessionExpiry.remove(sessionId, expiresAt);
            return false;
        }
        return true;
    }

    @Override
    protected void doRegisterSession(String userId, String sessionId) {
        userSessions.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(sessionId);
    }

    @Override
    protected void doCleanupSessionData(String userId, String sessionId) {
        if (sessionId != null) {
            invalidatedSessionExpiry.remove(sessionId);
            Set<String> sessions = userSessions.get(userId);
            if (sessions != null) {
                sessions.remove(sessionId);
            }
        }
    }

    @Override
    public void invalidateAllUserSessions(String userId, String reason) {
        if (userId == null) {
            return;
        }

        Set<String> sessions = userSessions.remove(userId);
        if (sessions != null) {
            for (String sessionId : sessions) {
                invalidateSession(sessionId, userId, reason);
            }
        }
    }
}
