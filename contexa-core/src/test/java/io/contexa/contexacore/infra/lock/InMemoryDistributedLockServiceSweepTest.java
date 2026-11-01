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

import io.contexa.contexacore.autonomous.store.InMemoryStateSweeper;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Z-16 (F4, item 6): a lock past its timeout no longer stays in memory until its key is used again; the shared sweep releases
 * it, as Redis expires the lock's key, and leaves a lock in force.
 */
class InMemoryDistributedLockServiceSweepTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryDistributedLockService locks = new InMemoryDistributedLockService(clock);

    @Test
    void theSweepReleasesALockPastItsTimeoutAndKeepsALockInForce() {
        assertThat(locks.tryLock("lapsed", "first", Duration.ofSeconds(1))).isTrue();
        assertThat(locks.tryLock("held", "second", Duration.ofMinutes(10))).isTrue();
        clock.advance(Duration.ofSeconds(2));
        assertThat(locks.holdsLockFor("lapsed")).as("past its timeout, not used again").isTrue();

        InMemoryStateSweeper sweeper = new InMemoryStateSweeper(() -> List.of(locks), Duration.ofDays(1));
        try {
            sweeper.sweep();
        } finally {
            sweeper.close();
        }

        assertThat(locks.holdsLockFor("lapsed")).isFalse();
        assertThat(locks.holdsLockFor("held")).isTrue();
        assertThat(locks.isLocked("held")).isTrue();
        assertThat(locks.getLockInfo("held").getOwner()).isEqualTo("second");
    }
}
