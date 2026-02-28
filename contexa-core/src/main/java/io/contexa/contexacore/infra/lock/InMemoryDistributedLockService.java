package io.contexa.contexacore.infra.lock;

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of DistributedLockService for standalone mode.
 * Uses ConcurrentHashMap with synchronized blocks instead of Redis Lua scripts.
 * Sufficient for single-JVM deployments.
 */
@Slf4j
public class InMemoryDistributedLockService implements DistributedLockService {

    private final ConcurrentHashMap<String, LockEntry> locks = new ConcurrentHashMap<>();

    @Override
    public boolean tryLock(String resourceKey, String owner, Duration timeout) {
        if (resourceKey == null || resourceKey.isBlank() || owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("resourceKey and owner must not be null or blank");
        }

        synchronized (locks) {
            LockEntry existing = locks.get(resourceKey);

            if (existing == null || existing.isExpired()) {
                locks.put(resourceKey, new LockEntry(owner, 1, computeExpiry(timeout)));
                return true;
            }

            if (existing.owner.equals(owner)) {
                existing.count++;
                existing.expiresAt = computeExpiry(timeout);
                return true;
            }

            return false;
        }
    }

    @Override
    public boolean unlock(String resourceKey, String owner) {
        if (resourceKey == null || resourceKey.isBlank() || owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("resourceKey and owner must not be null or blank");
        }

        synchronized (locks) {
            LockEntry entry = locks.get(resourceKey);
            if (entry == null) {
                return false;
            }
            if (!entry.owner.equals(owner)) {
                return false;
            }
            entry.count--;
            if (entry.count <= 0) {
                locks.remove(resourceKey);
            }
            return true;
        }
    }

    @Override
    public <T> T executeWithLock(String resourceKey, Duration timeout, LockableOperation<T> operation) {
        String owner = Thread.currentThread().getName() + ":" + UUID.randomUUID();

        if (!tryLock(resourceKey, owner, timeout)) {
            throw new LockAcquisitionException("Failed to acquire lock: " + resourceKey);
        }

        try {
            return operation.execute();
        } catch (LockAcquisitionException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Operation failed while holding lock: " + resourceKey, e);
        } finally {
            unlock(resourceKey, owner);
        }
    }

    @Override
    public boolean tryLockWithWait(String resourceKey, String owner, Duration timeout, Duration waitTime) {
        long deadline = System.currentTimeMillis() + waitTime.toMillis();
        long sleepMs = 50;

        while (System.currentTimeMillis() < deadline) {
            if (tryLock(resourceKey, owner, timeout)) {
                return true;
            }
            try {
                Thread.sleep(Math.min(sleepMs, deadline - System.currentTimeMillis()));
                sleepMs = Math.min(sleepMs * 2, 1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    @Override
    public LockInfo getLockInfo(String resourceKey) {
        if (resourceKey == null) {
            return null;
        }
        LockEntry entry = locks.get(resourceKey);
        if (entry == null || entry.isExpired()) {
            return null;
        }
        long ttl = Duration.between(Instant.now(), entry.expiresAt).getSeconds();
        return new LockInfo(entry.owner, entry.count, Math.max(0, ttl));
    }

    @Override
    public boolean forceUnlock(String resourceKey) {
        if (resourceKey == null) {
            return false;
        }
        return locks.remove(resourceKey) != null;
    }

    @Override
    public void clearAllLocks() {
        locks.clear();
    }

    @Override
    public boolean isLocked(String resourceKey) {
        if (resourceKey == null) {
            return false;
        }
        LockEntry entry = locks.get(resourceKey);
        return entry != null && !entry.isExpired();
    }

    private Instant computeExpiry(Duration timeout) {
        return timeout != null ? Instant.now().plus(timeout) : Instant.now().plusSeconds(30);
    }

    private static class LockEntry {
        final String owner;
        int count;
        Instant expiresAt;

        LockEntry(String owner, int count, Instant expiresAt) {
            this.owner = owner;
            this.count = count;
            this.expiresAt = expiresAt;
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }
}
