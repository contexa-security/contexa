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

import io.contexa.contexacore.infra.lock.DistributedLockService.LockAcquisitionException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Z-16 (4.3, F4): the in-memory and the Redis lock services answer alike. A lock lasts the timeout it was taken with,
 * under a second too, and thirty seconds without one; keys that differ are different locks whatever characters they
 * hold; a lock past its timeout is lost to its owner; a failing operation is wrapped the same way; blank arguments are
 * refused the same way.
 */
abstract class AbstractDistributedLockServiceContractTest {

    protected DistributedLockService locks;
    private final List<String> keys = new ArrayList<>();
    private final String prefix = "z16-lock-" + UUID.randomUUID() + ":";

    protected abstract DistributedLockService createLockService();

    @BeforeEach
    void setUpLocks() {
        locks = createLockService();
    }

    @AfterEach
    void releaseLocks() {
        keys.forEach(locks::forceUnlock);
    }

    @Test
    void aLockLastsItsTimeoutEvenUnderASecond() throws InterruptedException {
        String key = key("short");
        assertThat(locks.tryLock(key, "first", Duration.ofMillis(300))).isTrue();
        assertThat(locks.tryLock(key, "second", Duration.ofSeconds(30))).isFalse();

        Thread.sleep(700);

        assertThat(locks.isLocked(key)).isFalse();
        assertThat(locks.tryLock(key, "second", Duration.ofSeconds(30))).isTrue();
    }

    @Test
    void aLockKeepsTheTimeoutItWasTakenWith() {
        String key = key("long");
        assertThat(locks.tryLock(key, "first", Duration.ofMinutes(2))).isTrue();

        assertThat(locks.getLockInfo(key).getTtlSeconds()).isBetween(60L, 120L);
        assertThat(locks.getLockInfo(key).getOwner()).isEqualTo("first");
        assertThat(locks.getLockInfo(key).getCount()).isEqualTo(1);
    }

    @Test
    void aLockWithoutATimeoutLastsThirtySeconds() {
        String key = key("default");
        assertThat(locks.tryLock(key, "first", null)).isTrue();

        assertThat(locks.getLockInfo(key).getTtlSeconds()).isBetween(20L, 30L);
    }

    @Test
    void keysThatDifferAreDifferentLocksWhateverCharactersTheyHold() {
        assertThat(locks.tryLock(key("mfa:challenge:init:a@b.com"), "first", Duration.ofSeconds(30))).isTrue();
        assertThat(locks.tryLock(key("mfa:challenge:init:a#b.com"), "second", Duration.ofSeconds(30))).isTrue();
        assertThat(locks.tryLock(key("mfa:challenge:init:a_b.com"), "third", Duration.ofSeconds(30))).isTrue();
        String longKey = "mfa:challenge:init:" + "x".repeat(200);
        assertThat(locks.tryLock(key(longKey + "1"), "fourth", Duration.ofSeconds(30))).isTrue();
        assertThat(locks.tryLock(key(longKey + "2"), "fifth", Duration.ofSeconds(30))).isTrue();
    }

    @Test
    void aLockPastItsTimeoutIsLostToItsOwner() throws InterruptedException {
        String key = key("lost");
        assertThat(locks.tryLock(key, "first", Duration.ofMillis(300))).isTrue();

        Thread.sleep(700);

        assertThat(locks.unlock(key, "first")).isFalse();
        assertThat(locks.getLockInfo(key)).isNull();
    }

    @Test
    void aReentrantLockIsReleasedByAsManyUnlocksAndNotByAnotherOwner() {
        String key = key("reentrant");
        assertThat(locks.tryLock(key, "first", Duration.ofSeconds(30))).isTrue();
        assertThat(locks.tryLock(key, "first", Duration.ofSeconds(30))).isTrue();

        assertThat(locks.unlock(key, "second")).isFalse();
        assertThat(locks.unlock(key, "first")).isTrue();
        assertThat(locks.isLocked(key)).isTrue();
        assertThat(locks.unlock(key, "first")).isTrue();
        assertThat(locks.isLocked(key)).isFalse();
        assertThat(locks.unlock(key, "first")).isFalse();
    }

    @Test
    void aFailingOperationIsWrappedAndReleasesTheLock() {
        String key = key("operation");
        IllegalStateException failure = new IllegalStateException("operation failed");

        assertThatThrownBy(() -> locks.executeWithLock(key, Duration.ofSeconds(30), () -> {
            throw failure;
        })).isExactlyInstanceOf(RuntimeException.class)
                .hasMessage("Operation failed while holding lock: " + key)
                .hasCause(failure);
        assertThat(locks.isLocked(key)).isFalse();
        assertThat(locks.executeWithLock(key, Duration.ofSeconds(30), () -> "done")).isEqualTo("done");
    }

    @Test
    void aBusyLockFailsTheOperationWithoutRunningIt() {
        String key = key("busy");
        assertThat(locks.tryLock(key, "first", Duration.ofSeconds(30))).isTrue();

        assertThatThrownBy(() -> locks.executeWithLock(key, Duration.ofSeconds(30), () -> "never"))
                .isInstanceOf(LockAcquisitionException.class);
        assertThat(locks.getLockInfo(key).getOwner()).isEqualTo("first");
    }

    @Test
    void blankArgumentsAreRefusedAlike() {
        String key = key("arguments");
        assertThatThrownBy(() -> locks.tryLock(null, "first", Duration.ofSeconds(30)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> locks.tryLock(" ", "first", Duration.ofSeconds(30)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> locks.tryLock(key, " ", Duration.ofSeconds(30)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> locks.unlock(key, null)).isInstanceOf(IllegalArgumentException.class);
        assertThat(locks.isLocked(null)).isFalse();
        assertThat(locks.getLockInfo(null)).isNull();
        assertThat(locks.forceUnlock(null)).isFalse();
    }

    /** A key of this test, released afterwards. */
    private String key(String name) {
        String key = prefix + name;
        keys.add(key);
        return key;
    }
}
