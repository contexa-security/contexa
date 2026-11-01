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
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: the records held for verification and promotion learning share one byte budget, counted at two bytes a
 * character; past it the records held the longest ago are released first, whoever holds them. The bytes counted follow
 * every path that holds, replaces, takes or removes a record, and never go below zero.
 */
class InMemorySecurityContextDataStoreHeldLearningBudgetTest {

    private static final long MIB = 1024L * 1024;

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
            Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);

    @Test
    void pastTheDefaultBudgetTheRecordsHeldTheLongestAgoGoFirst() {
        InMemorySecurityContextDataStore defaultStore = new InMemorySecurityContextDataStore();
        // 2 MiB as counted (two bytes a character); 600 of them pass the largest default budget, 1 GiB.
        String record = "x".repeat(1 << 20);
        int users = 600;
        for (int user = 0; user < users; user++) {
            defaultStore.holdVerificationLearning("user-" + user, "request", record);
        }

        boolean[] held = new boolean[users];
        for (int user = 0; user < users; user++) {
            held[user] = defaultStore.takeVerificationLearning("user-" + user, "request") != null;
        }
        assertThat(held[0]).as("the record held first is still held").isFalse();
        assertThat(held[users - 1]).as("the record held last is held").isTrue();
        int firstHeld = 0;
        while (!held[firstHeld]) {
            firstHeld++;
        }
        for (int user = firstHeld; user < users; user++) {
            assertThat(held[user]).as("user-%d, held after the first one kept", user).isTrue();
        }
        assertThat((long) (users - firstHeld) * 2 * MIB).isLessThanOrEqualTo(defaultStore.heldLearningBudgetBytes());
        assertThat((long) (users - firstHeld + 1) * 2 * MIB).isGreaterThan(defaultStore.heldLearningBudgetBytes());
    }

    @Test
    void bothStoresShareTheBudgetAndTheOldestRecordsGoWhoeverHoldsThem() {
        store.setHeldLearningBudgetBytes(100_000);
        // 2,000 bytes as counted; 50 of them fill the budget.
        String record = "r".repeat(1_000);

        for (int user = 0; user < 200; user++) {
            if (user % 2 == 0) {
                store.holdVerificationLearning("user-" + user, "request-" + user, record);
            } else {
                store.holdPromotionLearning("user-" + user, "request-" + user, record);
            }
            assertThat(store.heldLearningBytes()).as("after user-%d", user).isLessThanOrEqualTo(100_000);
        }

        assertThat(store.heldLearningBytes()).isEqualTo(100_000);
        for (int user = 0; user < 200; user++) {
            String held = user % 2 == 0
                    ? store.takeVerificationLearning("user-" + user, "request-" + user)
                    : store.promotionLearning("user-" + user).get("request-" + user);
            if (user < 150) {
                assertThat(held).as("user-%d", user).isNull();
            } else {
                assertThat(held).as("user-%d", user).isEqualTo(record);
            }
        }
        assertThat(store.heldLearningBytes()).as("the 25 promotion records left").isEqualTo(25 * 2_000);
    }

    @Test
    void aRecordHeldWithinTheBudgetIsFoundByTheVerificationAndThePromotion() {
        store.setHeldLearningBudgetBytes(10_000);
        store.holdVerificationLearning("alice", "request-1", "{\"facts\":1}");
        store.holdPromotionLearning("alice", "request-2", "{\"facts\":2}");

        assertThat(store.heldLearningBytes()).isEqualTo(2L * ("{\"facts\":1}".length() + "{\"facts\":2}".length()));
        assertThat(store.promotionLearning("alice")).containsExactly(Map.entry("request-2", "{\"facts\":2}"));
        assertThat(store.takeVerificationLearning("alice", "request-1")).isEqualTo("{\"facts\":1}");
        assertThat(store.takeVerificationLearning("alice", "request-1")).isNull();
        assertThat(store.heldLearningBytes()).isEqualTo(2L * "{\"facts\":2}".length());
    }

    @Test
    void aRecordLargerThanTheWholeBudgetIsNotHeldAndReleasesNoOther() {
        store.setHeldLearningBudgetBytes(10_000);
        store.holdVerificationLearning("alice", "request-1", "a".repeat(1_000));
        store.holdVerificationLearning("bob", "request-2", "b".repeat(1_000));
        store.holdVerificationLearning("bob", "request-2", "c".repeat(6_000));

        assertThat(store.takeVerificationLearning("bob", "request-2")).as("not held, nor the one it replaced").isNull();
        assertThat(store.takeVerificationLearning("alice", "request-1")).isEqualTo("a".repeat(1_000));
        assertThat(store.heldLearningBytes()).isZero();
    }

    @Test
    void theBytesFollowEveryReplacementAndRemoval() {
        String small = "s".repeat(100);
        String large = "l".repeat(300);

        store.holdVerificationLearning("alice", "request", small);
        store.holdVerificationLearning("alice", "request", large);
        assertThat(store.heldLearningBytes()).as("replaced").isEqualTo(600);

        for (int request = 0; request < 60; request++) {
            store.holdVerificationLearning("bob", "request-" + request, small);
        }
        // Z-16 D-7: as in Redis, a user holds any number of records; the budget alone bounds them.
        assertThat(store.heldLearningBytes()).as("bob keeps all 60").isEqualTo(600 + 60 * 200);
        for (int request = 0; request < 210; request++) {
            store.holdPromotionLearning("carol", "request-" + request, small);
        }
        assertThat(store.heldLearningBytes()).as("carol keeps all 210").isEqualTo(600 + 270 * 200);

        store.removePromotionLearning("carol", List.of("request-209", "request-0", "missing"));
        assertThat(store.heldLearningBytes()).as("two of carol's removed").isEqualTo(600 + 268 * 200);
        assertThat(store.takeVerificationLearning("bob", "request-59")).isEqualTo(small);
        assertThat(store.heldLearningBytes()).as("one of bob's taken").isEqualTo(600 + 267 * 200);

        store.deleteUserData("alice");
        store.deleteUserData("bob");
        store.deleteUserData("carol");
        assertThat(store.heldLearningBytes()).isZero();
    }

    @Test
    void theRecordsOfADeletedAccountLeaveTheBytesInEveryTenantAndAgentKey() {
        store.holdVerificationLearning("dave", "request-1", "v".repeat(10));
        store.holdPromotionLearning("dave", "request-2", "p".repeat(20));
        store.holdPromotionLearning("tenant-a::dave", "request-3", "t".repeat(30));
        store.holdPromotionLearning("dave" + LearningSubject.AGENT_KEY + "agent-1", "request-4", "g".repeat(40));
        store.holdPromotionLearning("tenant-a::dave" + LearningSubject.AGENT_KEY + "agent-1", "request-5",
                "h".repeat(50));
        store.holdPromotionLearning("erin", "request-6", "e".repeat(60));
        assertThat(store.heldLearningBytes()).isEqualTo(2 * (10 + 20 + 30 + 40 + 50 + 60));

        store.deleteUserData("dave");

        assertThat(store.heldLearningBytes()).isEqualTo(2 * 60);
        assertThat(store.promotionLearning("tenant-a::dave")).isEmpty();
        assertThat(store.promotionLearning("erin")).containsKey("request-6");
    }

    @Test
    void theBytesFollowTheExpiryAndTheBoundOnUsers() {
        store.holdVerificationLearning("alice", "request-1", "a".repeat(10));
        store.holdPromotionLearning("alice", "request-2", "b".repeat(10));
        clock.advance(Duration.ofDays(31));
        store.removeExpiredEntries();
        assertThat(store.heldLearningBytes()).as("expired").isZero();

        for (int user = 0; user <= 10_000; user++) {
            store.holdVerificationLearning("user-" + user, "request", "x".repeat(5));
            clock.advance(Duration.ofMillis(1));
        }
        assertThat(store.keyCounts()).containsEntry("verificationLearning", 10_000);
        assertThat(store.heldLearningBytes()).as("one user released for the bound").isEqualTo(10_000 * 10);
        assertThat(store.takeVerificationLearning("user-0", "request")).isNull();
    }

    @Test
    void theReleaseOrderDropsTheEntriesOfRecordsNoLongerHeld() {
        for (int request = 0; request < 100_000; request++) {
            store.holdVerificationLearning("alice", "request-" + request, "{}");
            store.takeVerificationLearning("alice", "request-" + request);
        }
        store.holdVerificationLearning("alice", "kept", "{}");

        assertThat(store.heldLearningBytes()).isEqualTo(4);
        assertThat(store.heldLearningOrderEntries()).isLessThanOrEqualTo(2 + 1_024 + 1);
        assertThat(store.takeVerificationLearning("alice", "kept")).isEqualTo("{}");
    }

    @Test
    void theBytesMatchTheHeldRecordsAfterConcurrentWritesAndReturnToZero() throws Exception {
        store.setHeldLearningBudgetBytes(200_000);
        int users = 40;
        int requests = 20;
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> writers = new ArrayList<>();
            for (int thread = 0; thread < 8; thread++) {
                writers.add(executor.submit(() -> {
                    ThreadLocalRandom random = ThreadLocalRandom.current();
                    for (int operation = 0; operation < 5_000; operation++) {
                        String userId = "user-" + random.nextInt(users);
                        String requestId = "request-" + random.nextInt(requests);
                        int choice = random.nextInt(100);
                        if (choice < 40) {
                            store.holdVerificationLearning(userId, requestId, "v".repeat(random.nextInt(1, 2_000)));
                        } else if (choice < 75) {
                            store.holdPromotionLearning(userId, requestId, "p".repeat(random.nextInt(1, 2_000)));
                        } else if (choice < 88) {
                            store.takeVerificationLearning(userId, requestId);
                        } else if (choice < 97) {
                            store.removePromotionLearning(userId, List.of(requestId));
                        } else {
                            store.deleteUserData(userId);
                        }
                        assertThat(store.heldLearningBytes()).isNotNegative();
                    }
                }));
            }
            for (Future<?> writer : writers) {
                writer.get(2, TimeUnit.MINUTES);
            }
        } finally {
            executor.shutdownNow();
        }

        long counted = store.heldLearningBytes();
        assertThat(counted).isBetween(0L, 200_000L);
        long held = 0;
        for (int user = 0; user < users; user++) {
            for (String record : store.promotionLearning("user-" + user).values()) {
                held += 2L * record.length();
            }
            for (int request = 0; request < requests; request++) {
                String record = store.takeVerificationLearning("user-" + user, "request-" + request);
                held += record != null ? 2L * record.length() : 0;
            }
        }
        assertThat(counted).as("counted against held").isEqualTo(held);
        for (int user = 0; user < users; user++) {
            store.deleteUserData("user-" + user);
        }
        assertThat(store.heldLearningBytes()).isZero();
    }

    @Test
    void theDefaultBudgetIsATenthOfTheMaximumHeapBetweenSixteenMegabytesAndOneGigabyte() {
        assertThat(InMemorySecurityContextDataStore.defaultHeldLearningBudgetBytes(100 * MIB)).isEqualTo(16 * MIB);
        assertThat(InMemorySecurityContextDataStore.defaultHeldLearningBudgetBytes(512 * MIB)).isEqualTo(53_687_091L);
        assertThat(InMemorySecurityContextDataStore.defaultHeldLearningBudgetBytes(2048 * MIB))
                .isEqualTo(214_748_364L);
        assertThat(InMemorySecurityContextDataStore.defaultHeldLearningBudgetBytes(Long.MAX_VALUE))
                .isEqualTo(1024 * MIB);

        long derived = InMemorySecurityContextDataStore.defaultHeldLearningBudgetBytes(Runtime.getRuntime().maxMemory());
        assertThat(new InMemorySecurityContextDataStore().heldLearningBudgetBytes()).isEqualTo(derived);
        store.setHeldLearningBudgetBytes(4_096);
        assertThat(store.heldLearningBudgetBytes()).isEqualTo(4_096);
        store.setHeldLearningBudgetBytes(0);
        assertThat(store.heldLearningBudgetBytes()).isEqualTo(derived);
    }

    @Test
    void aSmallerBudgetReleasesTheOldestRecordsAtOnce() {
        store.holdVerificationLearning("alice", "request-1", "a".repeat(1_000));
        store.holdPromotionLearning("bob", "request-2", "b".repeat(1_000));
        store.holdVerificationLearning("carol", "request-3", "c".repeat(1_000));

        store.setHeldLearningBudgetBytes(4_000);

        assertThat(store.heldLearningBytes()).isEqualTo(4_000);
        assertThat(store.takeVerificationLearning("alice", "request-1")).isNull();
        assertThat(store.promotionLearning("bob")).containsKey("request-2");
        assertThat(store.takeVerificationLearning("carol", "request-3")).isNotNull();
    }
}
