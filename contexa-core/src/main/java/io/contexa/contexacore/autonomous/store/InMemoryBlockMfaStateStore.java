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
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import org.springframework.lang.Nullable;

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
        setVerified(userId, null);
    }

    @Override
    public void setVerified(String userId, @Nullable String contextBindingHash) {
        if (decisions != null) {
            decisions.setBlockMfaVerified(userId, verifiedTtl, contextBindingHash);
            return;
        }
        Instant now = clock.instant();
        verifications.put(ZeroTrustUserKey.of(userId), new Verification(now, now.plus(verifiedTtl), contextBindingHash));
    }

    @Override
    public boolean isVerified(String userId, @Nullable String contextBindingHash) {
        if (contextBindingHash == null || contextBindingHash.isEmpty()) {
            return false;
        }
        if (decisions != null) {
            return contextBindingHash.equals(decisions.getBlockMfaVerifiedContext(userId));
        }
        Verification verification = verifications.get(ZeroTrustUserKey.of(userId));
        return verification != null && contextBindingHash.equals(verification.contextBindingHash());
    }

    @Override
    public boolean isVerified(String userId) {
        if (decisions != null) {
            return decisions.getBlockMfaVerifiedUntil(userId) != null;
        }
        return verifications.containsKey(ZeroTrustUserKey.of(userId));
    }

    @Override
    public Instant getVerifiedAt(String userId) {
        if (decisions != null) {
            Instant until = decisions.getBlockMfaVerifiedUntil(userId);
            return until != null ? until.minus(verifiedTtl) : null;
        }
        Verification verification = verifications.get(ZeroTrustUserKey.of(userId));
        return verification != null ? verification.verifiedAt() : null;
    }

    @Override
    public Instant getVerifiedExpiresAt(String userId) {
        if (decisions != null) {
            return decisions.getBlockMfaVerifiedUntil(userId);
        }
        Verification verification = verifications.get(ZeroTrustUserKey.of(userId));
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
        verifications.remove(ZeroTrustUserKey.of(userId));
        actionRepository.clearBlockMfaPending(userId);
    }

    @Override
    public void removeExpiredEntries() {
        verifications.removeExpired();
    }

    boolean holdsVerificationFor(String userId) {
        return verifications.holds(ZeroTrustUserKey.of(userId))
                || (decisions != null && decisions.getBlockMfaVerifiedUntil(userId) != null);
    }

    /** When the user verified, when the verification lapses and the context it was passed in, if one was named. */
    private record Verification(Instant verifiedAt, Instant expiresAt, @Nullable String contextBindingHash) {
    }
}
