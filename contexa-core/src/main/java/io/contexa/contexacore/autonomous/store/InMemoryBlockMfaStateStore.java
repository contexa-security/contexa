package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryBlockMfaStateStore implements BlockMfaStateStore {

    private final ZeroTrustActionRepository actionRepository;
    private final Set<String> verifiedUsers = ConcurrentHashMap.newKeySet();
    private final Set<String> pendingUsers = ConcurrentHashMap.newKeySet();

    public InMemoryBlockMfaStateStore(ZeroTrustActionRepository actionRepository) {
        this.actionRepository = actionRepository;
    }

    @Override
    public void setVerified(String userId) {
        verifiedUsers.add(userId);
    }

    @Override
    public boolean isVerified(String userId) {
        return verifiedUsers.contains(userId);
    }

    @Override
    public void setPending(String userId) {
        pendingUsers.add(userId);
    }

    @Override
    public void clearPending(String userId) {
        pendingUsers.remove(userId);
    }

    @Override
    public int getFailCount(String userId) {
        return (int) actionRepository.getBlockMfaFailCount(userId);
    }
}
