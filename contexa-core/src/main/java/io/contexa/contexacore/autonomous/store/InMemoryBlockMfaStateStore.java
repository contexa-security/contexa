package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryBlockMfaStateStore implements BlockMfaStateStore {

    private static final Duration VERIFIED_TTL = Duration.ofHours(1);

    private final ZeroTrustActionRepository actionRepository;
    private final ConcurrentHashMap<String, Instant> verifiedExpiry = new ConcurrentHashMap<>();

    public InMemoryBlockMfaStateStore(ZeroTrustActionRepository actionRepository) {
        this.actionRepository = actionRepository;
    }

    @Override
    public void setVerified(String userId) {
        verifiedExpiry.put(userId, Instant.now().plus(VERIFIED_TTL));
    }

    @Override
    public boolean isVerified(String userId) {
        Instant expiry = verifiedExpiry.get(userId);
        if (expiry == null) {
            return false;
        }
        if (Instant.now().isAfter(expiry)) {
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
