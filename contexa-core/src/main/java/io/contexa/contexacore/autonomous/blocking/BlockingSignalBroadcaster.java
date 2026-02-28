package io.contexa.contexacore.autonomous.blocking;

/**
 * Abstraction for broadcasting block/unblock signals across instances.
 * Implementations: BlockingDecisionRegistry (distributed/Redisson), InMemoryBlockingSignalBroadcaster (standalone).
 */
public interface BlockingSignalBroadcaster {

    void registerBlock(String userId);

    void registerUnblock(String userId);

    boolean isBlocked(String userId);
}
