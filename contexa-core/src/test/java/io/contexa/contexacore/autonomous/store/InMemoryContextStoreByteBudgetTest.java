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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The session histories and the work profile observations of the in-memory context store each have a limit
 * in bytes. Below it nothing a decision reads changes; past it the sessions and the users written the longest ago go
 * first, whole. The count follows every path that adds, trims, moves, expires or removes a record.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class InMemoryContextStoreByteBudgetTest {

    /** A record of 500 characters: 1,000 bytes at two a character and 64 for its place. */
    private static final String RECORD = "r".repeat(500);
    private static final long RECORD_BYTES = 1_064;

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
            Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);

    private void historyOf(String session, int records) {
        for (int record = 0; record < records; record++) {
            store.addSessionDecision(session, RECORD);
        }
        clock.advance(Duration.ofMillis(1));
    }

    // ----- session histories -----

    @Test
    void belowTheLimitEveryRecordOfEverySessionStays() {
        store.setSessionHistoryBudgetBytes(100 * RECORD_BYTES);
        for (int session = 0; session < 10; session++) {
            historyOf("session-" + session, 10);
        }

        for (int session = 0; session < 10; session++) {
            assertThat(store.getRecentSessionDecisions("session-" + session, 100)).hasSize(10);
        }
        assertThat(store.sessionHistoryBytes()).isEqualTo(100 * RECORD_BYTES);
    }

    @Test
    void pastTheLimitTheSessionWrittenTheLongestAgoGoesWhole() {
        store.setSessionHistoryBudgetBytes(100 * RECORD_BYTES);
        store.addSessionAction("session-0", RECORD);
        store.addSessionNarrativeActionFamily("session-0", "READ");
        store.addSessionProtectableAccess("session-0", "/orders");
        store.addSessionRequestInterval("session-0", 100L);
        store.setSessionStartedAt("session-0", 1L);
        store.setSessionPreviousPath("session-0", "/orders");
        historyOf("session-0", 10);
        for (int session = 1; session < 10; session++) {
            historyOf("session-" + session, 10);
        }

        historyOf("session-new", 10);

        assertThat(store.getRecentSessionDecisions("session-0", 100)).isEmpty();
        assertThat(store.getRecentSessionActions("session-0", 100)).isEmpty();
        assertThat(store.getRecentSessionNarrativeActionFamilies("session-0", 100)).isEmpty();
        assertThat(store.getRecentSessionProtectableAccesses("session-0", 100)).isEmpty();
        assertThat(store.getRecentSessionRequestIntervals("session-0", 100)).isEmpty();
        assertThat(store.getSessionStartedAt("session-0")).isNull();
        assertThat(store.getSessionPreviousPath("session-0")).isNull();
        for (int session = 1; session < 10; session++) {
            assertThat(store.getRecentSessionDecisions("session-" + session, 100)).as("session-%d", session).hasSize(10);
        }
        assertThat(store.getRecentSessionDecisions("session-new", 100)).hasSize(10);
        assertThat(store.sessionHistoryBytes()).isLessThanOrEqualTo(100 * RECORD_BYTES);
    }

    @Test
    void aSessionWrittenAgainIsAmongTheNewest() {
        store.setSessionHistoryBudgetBytes(30 * RECORD_BYTES);
        historyOf("session-a", 10);
        historyOf("session-b", 10);
        historyOf("session-c", 10);
        historyOf("session-a", 0);
        store.addSessionDecision("session-a", RECORD);
        clock.advance(Duration.ofMillis(1));

        historyOf("session-d", 5);

        assertThat(store.getRecentSessionDecisions("session-b", 100)).as("written the longest ago").isEmpty();
        assertThat(store.getRecentSessionDecisions("session-a", 100)).hasSize(11);
    }

    @Test
    void whatASessionHoldsIsCountedOnceItsRecordsAreTrimmed() {
        for (int record = 0; record < 150; record++) {
            store.addSessionDecision("session-1", RECORD);
        }

        assertThat(store.getRecentSessionDecisions("session-1", 1_000)).hasSize(100);
        assertThat(store.sessionHistoryBytes()).isEqualTo(100 * RECORD_BYTES);
    }

    @Test
    void aSessionMovedToANewIdKeepsItsRecordsCountedOnce() {
        historyOf("old-id", 10);
        historyOf("new-id", 5);

        store.moveSessionRecords("old-id", "new-id");

        assertThat(store.getRecentSessionDecisions("new-id", 100)).hasSize(15);
        assertThat(store.sessionHistoryBytes()).isEqualTo(15 * RECORD_BYTES);
    }

    @Test
    void aMovedSessionIsCutToItsLimitAndCountedAtWhatItKeeps() {
        historyOf("old-id", 80);
        historyOf("new-id", 80);

        store.moveSessionRecords("old-id", "new-id");

        assertThat(store.getRecentSessionDecisions("new-id", 1_000)).hasSize(100);
        assertThat(store.sessionHistoryBytes()).isEqualTo(100 * RECORD_BYTES);
    }

    @Test
    void anExpiredHistoryLeavesTheCount() {
        historyOf("session-1", 10);

        clock.advance(Duration.ofHours(25));
        store.removeExpiredEntries();

        assertThat(store.sessionHistoryBytes()).isZero();
    }

    @Test
    void aHistoryEvictedForTheBoundOnSessionsLeavesTheCount() {
        for (int session = 0; session < 10_050; session++) {
            store.addSessionDecision("session-" + session, "d");
            clock.advance(Duration.ofMillis(1));
        }

        assertThat(store.keyCounts().get("sessionDecisions")).isLessThanOrEqualTo(10_000);
        assertThat(store.sessionHistoryBytes()).isEqualTo(store.keyCounts().get("sessionDecisions") * 66L);
    }

    @Test
    void aSessionLargerThanTheWholeLimitDoesNotStayOverIt() {
        store.setSessionHistoryBudgetBytes(5 * RECORD_BYTES);
        historyOf("session-a", 3);

        historyOf("session-b", 10);

        assertThat(store.sessionHistoryBytes()).isLessThanOrEqualTo(5 * RECORD_BYTES);
    }

    // ----- work profile observations -----

    private void observationsOf(String user, int observations) {
        for (int observation = 0; observation < observations; observation++) {
            store.addWorkProfileObservation("tenant", user, RECORD);
        }
        clock.advance(Duration.ofMillis(1));
    }

    @Test
    void belowTheLimitEveryObservationStays() {
        store.setWorkProfileBudgetBytes(100 * RECORD_BYTES);
        for (int user = 0; user < 10; user++) {
            observationsOf("user-" + user, 10);
        }

        for (int user = 0; user < 10; user++) {
            assertThat(store.getRecentWorkProfileObservations("tenant", "user-" + user, 100)).hasSize(10);
        }
        assertThat(store.workProfileBytes()).isEqualTo(100 * RECORD_BYTES);
    }

    @Test
    void pastTheLimitTheUserWrittenTheLongestAgoGoesWhole() {
        store.setWorkProfileBudgetBytes(30 * RECORD_BYTES);
        observationsOf("user-a", 10);
        observationsOf("user-b", 10);
        observationsOf("user-c", 10);

        observationsOf("user-d", 5);

        assertThat(store.getRecentWorkProfileObservations("tenant", "user-a", 100)).isEmpty();
        assertThat(store.getRecentWorkProfileObservations("tenant", "user-b", 100)).hasSize(10);
        assertThat(store.getRecentWorkProfileObservations("tenant", "user-d", 100)).hasSize(5);
        assertThat(store.workProfileBytes()).isEqualTo(25 * RECORD_BYTES);
    }

    @Test
    void aUserAtTheObservationCapacityIsCountedAtWhatItKeeps() {
        store.setObservationCapacity(20);

        observationsOf("user-a", 30);

        assertThat(store.workProfileBytes()).isEqualTo(20 * RECORD_BYTES);
    }

    @Test
    void aDeletedUsersObservationsLeaveTheCount() {
        observationsOf("user-a", 10);
        observationsOf("user-b", 10);

        store.deleteUserData("user-a");

        assertThat(store.workProfileBytes()).isEqualTo(10 * RECORD_BYTES);
    }

    @Test
    void anAgentsDeletedLearningLeavesTheCount() {
        store.addWorkProfileObservation("tenant", "owner" + LearningSubject.AGENT_KEY + "bot-1", RECORD);

        assertThat(store.deleteAgentLearning("bot-1")).isEqualTo(1);

        assertThat(store.workProfileBytes()).isZero();
    }

    @Test
    void expiredObservationsLeaveTheCount() {
        observationsOf("user-a", 10);

        clock.advance(Duration.ofDays(31));
        store.removeExpiredEntries();

        assertThat(store.workProfileBytes()).isZero();
    }

    @Test
    void theRoleScopeObservationsAreNotCountedAgainstTheWorkProfiles() {
        store.addRoleScopeObservation("tenant", "ROLE_USER", RECORD);

        assertThat(store.workProfileBytes()).isZero();
    }

    // ----- the two limits -----

    @Test
    void theDefaultLimitIsATwentiethOfTheHeapBetween16And512MiB() {
        long mib = 1024L * 1024;
        assertThat(ExpiringKeyBudget.defaultLimitBytes(64 * mib)).isEqualTo(16 * mib);
        assertThat(ExpiringKeyBudget.defaultLimitBytes(2_048 * mib)).isEqualTo(2_048 * mib / 20);
        assertThat(ExpiringKeyBudget.defaultLimitBytes(32_768 * mib)).isEqualTo(512 * mib);
        assertThat(ExpiringKeyBudget.defaultLimitBytes(Long.MAX_VALUE)).isEqualTo(512 * mib);
        assertThat(new InMemorySecurityContextDataStore().sessionHistoryBudgetBytes())
                .isEqualTo(ExpiringKeyBudget.defaultLimitBytes(Runtime.getRuntime().maxMemory()));
        assertThat(new InMemorySecurityContextDataStore().workProfileBudgetBytes())
                .isEqualTo(ExpiringKeyBudget.defaultLimitBytes(Runtime.getRuntime().maxMemory()));
    }

    @RepeatedTest(5)
    void writersAtOnceStayWithinTheLimitAndTheCountEndsAtZero() throws Exception {
        long limit = 200 * RECORD_BYTES;
        store.setSessionHistoryBudgetBytes(limit);
        store.setWorkProfileBudgetBytes(limit);
        ExecutorService threads = Executors.newFixedThreadPool(8);
        List<Future<?>> writers = new ArrayList<>();
        for (int writer = 0; writer < 8; writer++) {
            writers.add(threads.submit(() -> {
                ThreadLocalRandom random = ThreadLocalRandom.current();
                for (int write = 0; write < 2_000; write++) {
                    String session = "session-" + random.nextInt(40);
                    switch (random.nextInt(5)) {
                        case 0 -> store.addSessionDecision(session, RECORD);
                        case 1 -> store.addSessionAction(session, RECORD);
                        case 2 -> store.moveSessionRecords(session, "session-" + random.nextInt(40));
                        case 3 -> store.addWorkProfileObservation("tenant", "user-" + random.nextInt(40), RECORD);
                        default -> store.deleteUserData("user-" + random.nextInt(40));
                    }
                }
                return null;
            }));
        }
        for (Future<?> writer : writers) {
            writer.get();
        }
        threads.shutdown();

        assertThat(store.sessionHistoryBytes()).isBetween(0L, limit);
        assertThat(store.workProfileBytes()).isBetween(0L, limit);

        clock.advance(Duration.ofDays(31));
        store.removeExpiredEntries();

        assertThat(store.sessionHistoryBytes()).isZero();
        assertThat(store.workProfileBytes()).isZero();
    }
}
