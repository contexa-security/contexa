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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: the in-memory decision store keeps a bounded number of users. Past the bound the users whose decision was
 * written the longest ago go first; a user whose state restricts never goes, nor one decided within its TTL.
 */
class InMemoryZeroTrustActionRepositoryUserBoundTest {

    private static final Duration ALLOW_VALIDITY = Duration.ofSeconds(15);

    /** Longer than the ALLOW's TTL here, so the user written before is no longer decided within it. */
    private static final Duration PAST_ALLOW_TTL = Duration.ofSeconds(20);

    private final AdjustableClock clock = new AdjustableClock();

    @Test
    void pastTheBoundTheUsersWrittenTheLongestAgoGoFirst() {
        InMemoryZeroTrustActionRepository repository = bounded(3);

        for (int user = 1; user <= 5; user++) {
            repository.saveAction("user-" + user, ZeroTrustAction.ALLOW, Map.of());
            clock.advance(PAST_ALLOW_TTL);
        }

        assertThat(repository.userCount()).isEqualTo(3);
        assertThat(repository.holdsStateFor("user-1")).isFalse();
        assertThat(repository.holdsStateFor("user-2")).isFalse();
        assertThat(repository.holdsLockFor("user-1")).isFalse();
        for (int user = 3; user <= 5; user++) {
            assertThat(repository.getLastVerifiedAction("user-" + user)).isEqualTo(ZeroTrustAction.ALLOW);
        }
    }

    @Test
    void aUserWhoseStateRestrictsIsNeverReleased() {
        InMemoryZeroTrustActionRepository repository = bounded(2);
        repository.saveAction("blocked", ZeroTrustAction.ALLOW, Map.of());
        repository.setBlockedFlag("blocked");
        repository.saveAction("challenged", ZeroTrustAction.CHALLENGE, Map.of());
        repository.saveAction("escalated", ZeroTrustAction.ESCALATE, Map.of());
        repository.setBlockMfaPending("mfa-pending");
        repository.incrementBlockMfaFailCount("mfa-failing");
        repository.setEscalateRetry("retrying", Duration.ofHours(1));
        repository.markDecisionAuditPending("audited", "ctx", Duration.ofHours(1));
        // The ESCALATE passes its TTL unresolved: it still reads as ESCALATE through its last verified record.
        clock.advance(Duration.ofMinutes(6));

        for (int visitor = 1; visitor <= 5; visitor++) {
            repository.saveAction("visitor-" + visitor, ZeroTrustAction.ALLOW, Map.of());
            clock.advance(PAST_ALLOW_TTL);
        }
        repository.removeExpiredEntries();

        assertThat(repository.getCurrentAction("blocked", "ctx")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction("challenged", "ctx")).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction("escalated", "ctx")).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.isBlockMfaPending("mfa-pending")).isTrue();
        assertThat(repository.getBlockMfaFailCount("mfa-failing")).isEqualTo(1);
        assertThat(repository.hasEscalateRetry("retrying")).isTrue();
        assertThat(repository.isDecisionAuditPending("audited", "ctx")).isTrue();
        for (int visitor = 1; visitor <= 5; visitor++) {
            assertThat(repository.holdsStateFor("visitor-" + visitor)).as("visitor-%d", visitor).isFalse();
        }
        assertThat(repository.userCount()).isEqualTo(7);
    }

    @Test
    void aUserDecidedWithinItsTtlStaysUntilItLapses() {
        InMemoryZeroTrustActionRepository repository = bounded(1);
        repository.saveAction("first", ZeroTrustAction.ALLOW, Map.of());
        clock.advance(Duration.ofSeconds(1));
        repository.saveAction("second", ZeroTrustAction.ALLOW, Map.of());

        assertThat(repository.getCurrentAction("first", null)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.userCount()).isEqualTo(2);

        clock.advance(PAST_ALLOW_TTL);
        repository.removeExpiredEntries();

        assertThat(repository.holdsStateFor("first")).isFalse();
        assertThat(repository.getLastVerifiedAction("second")).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    void aUserWrittenAgainAfterItWasChosenIsNotReleased() {
        InMemoryZeroTrustActionRepository repository = bounded(20);
        for (int user = 1; user <= 21; user++) {
            repository.saveAction("user-" + user, ZeroTrustAction.ALLOW, Map.of());
            clock.advance(PAST_ALLOW_TTL);
        }
        // The 21st user released user-1 and left user-2 chosen as the next one.
        assertThat(repository.holdsStateFor("user-1")).isFalse();
        assertThat(repository.holdsStateFor("user-2")).isTrue();

        repository.saveAction("user-2", ZeroTrustAction.ALLOW, Map.of());
        clock.advance(PAST_ALLOW_TTL);
        repository.saveAction("user-22", ZeroTrustAction.ALLOW, Map.of());

        assertThat(repository.holdsStateFor("user-2")).isTrue();
        assertThat(repository.holdsStateFor("user-3")).isFalse();
        assertThat(repository.holdsStateFor("user-4")).isTrue();
        assertThat(repository.userCount()).isEqualTo(20);
    }

    @Test
    void theDefaultBoundIsATwentiethOfTheHeapAtTwoKibibytesAUser() {
        assertThat(InMemoryZeroTrustActionRepository.defaultMaxUsers(512L << 20)).isEqualTo(13_107);
        assertThat(InMemoryZeroTrustActionRepository.defaultMaxUsers(2L << 30)).isEqualTo(52_428);
        assertThat(InMemoryZeroTrustActionRepository.defaultMaxUsers(8L << 30)).isEqualTo(209_715);
        assertThat(InMemoryZeroTrustActionRepository.defaultMaxUsers(32L << 20)).isEqualTo(1_000);
        assertThat(InMemoryZeroTrustActionRepository.defaultMaxUsers(Long.MAX_VALUE)).isEqualTo(1_000_000);
        assertThat(new InMemoryZeroTrustActionRepository(0).maxUsers())
                .isEqualTo(InMemoryZeroTrustActionRepository.defaultMaxUsers(Runtime.getRuntime().maxMemory()));
        assertThat(new InMemoryZeroTrustActionRepository(250).maxUsers()).isEqualTo(250);
    }

    @Test
    void releasingUnderConcurrentWritesNeverReleasesABlockedUser() throws Exception {
        InMemoryZeroTrustActionRepository repository = bounded(100);
        AtomicBoolean running = new AtomicBoolean(true);
        Thread sweeper = new Thread(() -> {
            while (running.get()) {
                clock.advance(Duration.ofSeconds(1));
                repository.removeExpiredEntries();
            }
        });
        sweeper.start();
        ExecutorService writers = Executors.newFixedThreadPool(4);
        List<String> blocked = new ArrayList<>();
        try {
            List<Future<?>> rounds = new ArrayList<>();
            for (int writer = 0; writer < 4; writer++) {
                int first = writer * 2_000;
                for (int user = first; user < first + 2_000; user += 50) {
                    blocked.add("user-" + user);
                }
                rounds.add(writers.submit(() -> {
                    for (int user = first; user < first + 2_000; user++) {
                        repository.saveAction("user-" + user, ZeroTrustAction.ALLOW, Map.of());
                        if (user % 50 == 0) {
                            repository.setBlockedFlag("user-" + user);
                        }
                    }
                }));
            }
            for (Future<?> round : rounds) {
                round.get(60, TimeUnit.SECONDS);
            }
        } finally {
            running.set(false);
            writers.shutdownNow();
            sweeper.join(10_000);
        }
        clock.advance(PAST_ALLOW_TTL);
        repository.removeExpiredEntries();

        for (String user : blocked) {
            assertThat(repository.getCurrentAction(user, "ctx")).as(user).isEqualTo(ZeroTrustAction.BLOCK);
        }
        assertThat(repository.userCount()).isLessThanOrEqualTo(100 + blocked.size());
    }

    private InMemoryZeroTrustActionRepository bounded(int maxUsers) {
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock, maxUsers);
        repository.setAllowValidity(ALLOW_VALIDITY);
        return repository;
    }
}
