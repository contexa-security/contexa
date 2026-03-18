package io.contexa.contexacore.autonomous.blocking;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of BlockingSignalBroadcaster for standalone mode.
 * Uses ConcurrentHashMap instead of Redisson RTopic for single-JVM deployments.
 */
public class InMemoryBlockingSignalBroadcaster implements BlockingSignalBroadcaster {

    private final ConcurrentHashMap<String, String> blockedUsers = new ConcurrentHashMap<>();

    @Override
    public void registerBlock(String userId, String action) {
        if (userId != null && !userId.isBlank()) {
            blockedUsers.put(userId, (action != null && !action.isBlank()) ? action : "BLOCK");
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
        return blockedUsers.containsKey(userId);
    }

    @Override
    public String getBlockAction(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        return blockedUsers.get(userId);
    }
}
