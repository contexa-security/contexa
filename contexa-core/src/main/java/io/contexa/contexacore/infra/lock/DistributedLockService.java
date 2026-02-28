package io.contexa.contexacore.infra.lock;

import java.time.Duration;

/**
 * Abstraction for distributed lock operations.
 * Implementations: RedisDistributedLockService (distributed), InMemoryDistributedLockService (standalone).
 */
public interface DistributedLockService {

    boolean tryLock(String resourceKey, String owner, Duration timeout);

    boolean unlock(String resourceKey, String owner);

    <T> T executeWithLock(String resourceKey, Duration timeout, LockableOperation<T> operation);

    boolean tryLockWithWait(String resourceKey, String owner, Duration timeout, Duration waitTime);

    LockInfo getLockInfo(String resourceKey);

    boolean forceUnlock(String resourceKey);

    void clearAllLocks();

    boolean isLocked(String resourceKey);

    @FunctionalInterface
    interface LockableOperation<T> {
        T execute() throws Exception;
    }

    class LockInfo {
        private final String owner;
        private final int count;
        private final long ttlSeconds;

        public LockInfo(String owner, int count, long ttlSeconds) {
            this.owner = owner;
            this.count = count;
            this.ttlSeconds = ttlSeconds;
        }

        public String getOwner() { return owner; }
        public int getCount() { return count; }
        public long getTtlSeconds() { return ttlSeconds; }
    }

    class LockAcquisitionException extends RuntimeException {
        public LockAcquisitionException(String message) {
            super(message);
        }
    }
}
