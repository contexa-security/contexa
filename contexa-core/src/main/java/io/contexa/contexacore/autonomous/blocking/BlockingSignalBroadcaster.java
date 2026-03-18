package io.contexa.contexacore.autonomous.blocking;

/**
 * Abstraction for broadcasting block/unblock signals across instances.
 * Implementations: BlockingDecisionRegistry (distributed/Redisson), InMemoryBlockingSignalBroadcaster (standalone).
 */
public interface BlockingSignalBroadcaster {

    default void registerBlock(String userId) {
        registerBlock(userId, "BLOCK");
    }

    void registerBlock(String userId, String action);

    void registerUnblock(String userId);

    boolean isBlocked(String userId);

    String getBlockAction(String userId);
}
