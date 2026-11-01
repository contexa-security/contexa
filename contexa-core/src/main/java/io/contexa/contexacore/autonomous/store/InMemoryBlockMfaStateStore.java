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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * In-memory BLOCK MFA state. Z-16 (1-d): with the in-memory decision repository the verification is kept there, as the
 * Redis keys sit side by side, so a logout of a user nothing restricts and the removal of the user's or agents' data
 * clear it with the pending flag and the failure count; with another repository it is kept here, in an
 * {@link ExpiringKeySpace} (N-1).
 */
public class InMemoryBlockMfaStateStore implements BlockMfaStateStore, ExpiringStateStore {

    private static final Duration DEFAULT_VERIFIED_TTL = Duration.ofHours(1);

    private final ZeroTrustActionRepository actionRepository;
    /** The in-memory decision repository that keeps the verification; null with another repository. */
    private final InMemoryZeroTrustActionRepository decisions;
    private final Duration verifiedTtl;
    private final Clock clock;
    /** Each verification kept here, for the verified TTL. */
    private final ExpiringKeySpace<Verification> verifications;

    public InMemoryBlockMfaStateStore(ZeroTrustActionRepository actionRepository) {
        this(actionRepository, DEFAULT_VERIFIED_TTL, Clock.systemUTC());
    }

    public InMemoryBlockMfaStateStore(ZeroTrustActionRepository actionRepository, Duration verifiedTtl) {
        this(actionRepository, verifiedTtl, Clock.systemUTC());
    }

    public InMemoryBlockMfaStateStore(ZeroTrustActionRepository actionRepository, Duration verifiedTtl, Clock clock) {
        this.actionRepository = Objects.requireNonNull(actionRepository, "actionRepository");
        this.decisions = actionRepository instanceof InMemoryZeroTrustActionRepository memory ? memory : null;
        this.verifiedTtl = Objects.requireNonNull(verifiedTtl, "verifiedTtl");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.verifications = ExpiringKeySpace.<Verification>builder(clock).ttl(verifiedTtl).build();
    }

    @Override
    public void setVerified(String userId) {
        if (decisions != null) {
            decisions.setBlockMfaVerified(userId, verifiedTtl);
            return;
        }
        Instant now = clock.instant();
        verifications.put(userId, new Verification(now, now.plus(verifiedTtl)));
    }

    @Override
    public boolean isVerified(String userId) {
        if (decisions != null) {
            return decisions.getBlockMfaVerifiedUntil(userId) != null;
        }
        return verifications.containsKey(userId);
    }

    @Override
    public Instant getVerifiedAt(String userId) {
        if (decisions != null) {
            Instant until = decisions.getBlockMfaVerifiedUntil(userId);
            return until != null ? until.minus(verifiedTtl) : null;
        }
        Verification verification = verifications.get(userId);
        return verification != null ? verification.verifiedAt() : null;
    }

    @Override
    public Instant getVerifiedExpiresAt(String userId) {
        if (decisions != null) {
            return decisions.getBlockMfaVerifiedUntil(userId);
        }
        Verification verification = verifications.get(userId);
        return verification != null ? verification.expiresAt() : null;
    }

    @Override
    public void setPending(String userId) {
        actionRepository.setBlockMfaPending(userId);
    }

    @Override
    public void clearPending(String userId) {
        actionRepository.clearBlockMfaPending(userId);
    }

    @Override
    public int getFailCount(String userId) {
        return (int) actionRepository.getBlockMfaFailCount(userId);
    }

    @Override
    public void clearUser(String userId) {
        if (userId == null) {
            return;
        }
        if (decisions != null) {
            decisions.clearBlockMfaVerified(userId);
        }
        verifications.remove(userId);
        actionRepository.clearBlockMfaPending(userId);
    }

    @Override
    public void removeExpiredEntries() {
        verifications.removeExpired();
    }

    boolean holdsVerificationFor(String userId) {
        return verifications.holds(userId)
                || (decisions != null && decisions.getBlockMfaVerifiedUntil(userId) != null);
    }

    /** When the user verified and when the verification lapses. */
    private record Verification(Instant verifiedAt, Instant expiresAt) {
    }
}
