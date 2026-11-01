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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: the sweep of the in-memory decision store releases what no read returns any more, each store on its own
 * (a last verified record after its 24 h, as its Redis key; a BLOCK and its flag never, as their Redis keys), without
 * changing any read, and a user's lock goes once nothing of the user is left and no thread holds it.
 */
class InMemoryZeroTrustActionRepositoryRedisParityTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryZeroTrustActionRepository repository =
            new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);

    @Test
    void aSweepChangesNoReadOfAnExpiredDecision() {
        repository.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of("reasoning", "challenged"));
        repository.saveAction("bob", ZeroTrustAction.ESCALATE, Map.of("reasoning", "held for review"));

        clock.advance(Duration.ofMinutes(31));
        repository.removeExpiredEntries();

        assertThat(repository.getCurrentAction("alice", "ctx")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        // QF-48 (stage 2): an analysis past its TTL is absent, as its Redis key is.
        assertThat(repository.getAnalysisData("alice").action()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS.name());
        assertThat(repository.getAnalysisData("alice").reasoning()).isNull();
        assertThat(repository.getLastVerifiedAction("alice")).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction("bob", "ctx")).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getCurrentAction("bob")).isEqualTo(ZeroTrustAction.ESCALATE);

        clock.advance(Duration.ofHours(24));
        repository.removeExpiredEntries();

        for (String user : new String[]{"alice", "bob"}) {
            assertThat(repository.getCurrentAction(user, "ctx")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
            assertThat(repository.holdsStateFor(user)).isFalse();
            assertThat(repository.holdsLockFor(user)).isFalse();
        }
    }

    @Test
    void theLastVerifiedRecordOfABlockGoesAfterItsDayWhileTheBlockStays() {
        repository.saveAction("carol", ZeroTrustAction.BLOCK, Map.of("reasoning", "blocked"));
        repository.setBlockedFlag("carol");

        clock.advance(Duration.ofHours(25));
        assertThat(repository.getLastVerifiedAction("carol")).isNull();
        repository.removeExpiredEntries();

        assertThat(repository.holdsLastVerifiedFor("carol")).isFalse();
        assertThat(repository.getCurrentAction("carol", "ctx")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getActionFromHash("carol")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getAnalysisData("carol").reasoning()).isEqualTo("blocked");
        assertThat(repository.holdsLockFor("carol")).isTrue();
    }

    @Test
    void theLockOfAUserWithNothingLeftIsRetiredBySweep() {
        repository.saveAction("dave", ZeroTrustAction.ALLOW, null);
        assertThat(repository.holdsLockFor("dave")).isTrue();

        clock.advance(Duration.ofHours(25));
        repository.removeExpiredEntries();

        assertThat(repository.holdsStateFor("dave")).isFalse();
        assertThat(repository.holdsLockFor("dave")).isFalse();
    }

    @Test
    void deletingAUsersDataRetiresItsLocks() {
        repository.saveAction("erin", ZeroTrustAction.CHALLENGE, null);
        repository.removeAllUserData("erin");
        assertThat(repository.holdsLockFor("erin")).isFalse();

        repository.saveAction("erin::agent::report-agent", ZeroTrustAction.ALLOW, null);
        repository.removeAllAgentData("erin");
        assertThat(repository.holdsLockFor("erin::agent::report-agent")).isFalse();
    }

    @Test
    void retiringUnusedLocksNeverLetsTwoWritersOfOneUserIn() throws Exception {
        AtomicInteger inside = new AtomicInteger();
        AtomicInteger overlaps = new AtomicInteger();
        AtomicBoolean writing = new AtomicBoolean(true);
        Thread sweeper = new Thread(() -> {
            while (writing.get()) {
                repository.removeExpiredEntries();
            }
        });
        sweeper.start();
        ExecutorService writers = Executors.newFixedThreadPool(4);
        try {
            List<Future<?>> rounds = new ArrayList<>();
            for (int writer = 0; writer < 4; writer++) {
                rounds.add(writers.submit(() -> {
                    for (int round = 0; round < 5_000; round++) {
                        ReentrantLock lock = repository.lockUser("gina");
                        try {
                            if (inside.incrementAndGet() != 1) {
                                overlaps.incrementAndGet();
                            }
                            Thread.onSpinWait();
                            inside.decrementAndGet();
                        } finally {
                            lock.unlock();
                        }
                    }
                }));
            }
            for (Future<?> round : rounds) {
                round.get(60, TimeUnit.SECONDS);
            }
        } finally {
            writing.set(false);
            writers.shutdownNow();
            sweeper.join(10_000);
        }

        assertThat(overlaps).hasValue(0);
        repository.removeExpiredEntries();
        assertThat(repository.holdsLockFor("gina")).isFalse();
    }

    @Test
    void anExpiredDecisionAuditMarkerLeavesNothingOfTheUser() {
        repository.markDecisionAuditPending("frank", "ctx", Duration.ofSeconds(30));

        clock.advance(Duration.ofMinutes(1));
        repository.removeExpiredEntries();

        assertThat(repository.isDecisionAuditPending("frank", "ctx")).isFalse();
        assertThat(repository.holdsStateFor("frank")).isFalse();
    }
}
