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
package io.contexa.contexacore.infra.lock;

import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import lombok.extern.slf4j.Slf4j;

import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

/**
 * In-memory implementation of DistributedLockService for standalone mode.
 * Each lock is a key of an {@link ExpiringKeySpace} (Z-16, N-1) that lasts the lock's timeout, changed at once as the
 * Redis scripts change the lock's key. Z-16 (F4): the sweep releases the locks past their timeout, as Redis expires
 * their keys. Sufficient for single-JVM deployments.
 */
@Slf4j
public class InMemoryDistributedLockService implements DistributedLockService, ExpiringStateStore {

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private final Clock clock;
    private final ExpiringKeySpace<LockEntry> locks;

    public InMemoryDistributedLockService() {
        this(Clock.systemUTC());
    }

    /** Measures the locks' timeouts with {@code clock}. */
    InMemoryDistributedLockService(Clock clock) {
        this.clock = clock;
        this.locks = ExpiringKeySpace.<LockEntry>builder(clock).build();
    }

    @Override
    public boolean tryLock(String resourceKey, String owner, Duration timeout) {
        if (resourceKey == null || resourceKey.isBlank() || owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("resourceKey and owner must not be null or blank");
        }

        return locks.atomically(resourceKey, slot -> {
            LockEntry existing = slot.value();

            if (existing == null) {
                slot.set(new LockEntry(owner, 1), timeoutOf(timeout));
                return true;
            }

            if (existing.owner().equals(owner)) {
                slot.set(new LockEntry(owner, existing.count() + 1), timeoutOf(timeout));
                return true;
            }

            return false;
        });
    }

    @Override
    public boolean unlock(String resourceKey, String owner) {
        if (resourceKey == null || resourceKey.isBlank() || owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("resourceKey and owner must not be null or blank");
        }

        return locks.atomically(resourceKey, slot -> {
            LockEntry entry = slot.value();
            // Z-16 (F4): a lock past its timeout is lost to its owner, as its Redis key is gone.
            if (entry == null || !entry.owner().equals(owner)) {
                return false;
            }
            if (entry.count() <= 1) {
                slot.delete();
            } else {
                slot.keep(new LockEntry(owner, entry.count() - 1));
            }
            return true;
        });
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
        return locks.atomically(resourceKey, slot -> {
            LockEntry entry = slot.value();
            if (entry == null) {
                return null;
            }
            long ttl = Math.floorDiv(slot.expiresAtMs() - clock.millis(), 1000L);
            return new LockInfo(entry.owner(), entry.count(), Math.max(0, ttl));
        });
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
        locks.removeIf(resourceKey -> true);
    }

    @Override
    public boolean isLocked(String resourceKey) {
        if (resourceKey == null) {
            return false;
        }
        return locks.containsKey(resourceKey);
    }

    @Override
    public void removeExpiredEntries() {
        locks.removeExpired();
    }

    /** Whether the lock still takes memory, past its timeout or not. */
    boolean holdsLockFor(String resourceKey) {
        return locks.holds(resourceKey);
    }

    private static Duration timeoutOf(Duration timeout) {
        return timeout != null ? timeout : DEFAULT_TIMEOUT;
    }

    /** The owner of a lock and how many times it holds it. */
    private record LockEntry(String owner, int count) {
    }
}
