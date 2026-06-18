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

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryBlockMfaStateStore implements BlockMfaStateStore {

    private static final Duration DEFAULT_VERIFIED_TTL = Duration.ofHours(1);

    private final ZeroTrustActionRepository actionRepository;
    private final Duration verifiedTtl;
    private final Clock clock;
    private final ConcurrentHashMap<String, Instant> verifiedAt = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> verifiedExpiry = new ConcurrentHashMap<>();

    public InMemoryBlockMfaStateStore(ZeroTrustActionRepository actionRepository) {
        this(actionRepository, DEFAULT_VERIFIED_TTL, Clock.systemUTC());
    }

    public InMemoryBlockMfaStateStore(ZeroTrustActionRepository actionRepository, Duration verifiedTtl) {
        this(actionRepository, verifiedTtl, Clock.systemUTC());
    }

    public InMemoryBlockMfaStateStore(ZeroTrustActionRepository actionRepository, Duration verifiedTtl, Clock clock) {
        this.actionRepository = Objects.requireNonNull(actionRepository, "actionRepository");
        this.verifiedTtl = Objects.requireNonNull(verifiedTtl, "verifiedTtl");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public void setVerified(String userId) {
        Instant now = clock.instant();
        verifiedAt.put(userId, now);
        verifiedExpiry.put(userId, now.plus(verifiedTtl));
    }

    @Override
    public boolean isVerified(String userId) {
        Instant expiry = verifiedExpiry.get(userId);
        if (expiry == null) {
            return false;
        }
        if (clock.instant().isAfter(expiry)) {
            verifiedExpiry.remove(userId);
            verifiedAt.remove(userId);
            return false;
        }
        return true;
    }

    @Override
    public Instant getVerifiedAt(String userId) {
        return isVerified(userId) ? verifiedAt.get(userId) : null;
    }

    @Override
    public Instant getVerifiedExpiresAt(String userId) {
        return isVerified(userId) ? verifiedExpiry.get(userId) : null;
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
}
