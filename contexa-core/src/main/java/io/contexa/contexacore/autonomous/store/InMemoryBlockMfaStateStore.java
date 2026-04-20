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
        verifiedExpiry.put(userId, clock.instant().plus(verifiedTtl));
    }

    @Override
    public boolean isVerified(String userId) {
        Instant expiry = verifiedExpiry.get(userId);
        if (expiry == null) {
            return false;
        }
        if (clock.instant().isAfter(expiry)) {
            verifiedExpiry.remove(userId);
            return false;
        }
        return true;
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
