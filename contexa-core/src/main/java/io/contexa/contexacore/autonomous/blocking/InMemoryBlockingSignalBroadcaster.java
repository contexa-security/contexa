package io.contexa.contexacore.autonomous.blocking;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of BlockingSignalBroadcaster for standalone mode.
 * Uses ConcurrentHashMap instead of Redisson RTopic for single-JVM deployments.
 */
public class InMemoryBlockingSignalBroadcaster implements BlockingSignalBroadcaster {

    private final Set<String> blockedUsers = ConcurrentHashMap.newKeySet();

    @Override
    public void registerBlock(String userId) {
        if (userId != null && !userId.isBlank()) {
            blockedUsers.add(userId);
        }
    }

    @Override
    public void registerUnblock(String userId) {
        if (userId != null) {
            blockedUsers.remove(userId);
        }
    }

    @Override
    public boolean isBlocked(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        return blockedUsers.contains(userId);
    }
}
