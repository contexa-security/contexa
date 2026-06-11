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
