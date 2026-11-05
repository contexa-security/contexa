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
package io.contexa.contexaidentity.security.zerotrust.stepup;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What a claim promises, the same in memory and in Redis: only the reach across nodes differs. Every case takes keys of
 * its own, so the Redis case flushes nothing on the server it runs against.
 */
abstract class AbstractStepUpOptionsStoreClaimContractTest {

    private static final int CALLERS = 20;

    protected abstract StepUpOptionsStore store();

    private static String key() {
        return "contract:" + UUID.randomUUID();
    }

    @Test
    @DisplayName("a claim goes to the first caller, and the next one finds it held")
    void aClaimGoesToTheFirstCaller() {
        StepUpOptionsStore store = store();
        String key = key();

        assertThat(store.claim(key, Duration.ofMinutes(1))).isTrue();
        assertThat(store.claim(key, Duration.ofMinutes(1))).isFalse();
    }

    @Test
    @DisplayName("a claim is held for the time given and no longer")
    void aClaimEndsWithItsTime() {
        StepUpOptionsStore store = store();
        String key = key();
        Duration hold = Duration.ofMillis(500);

        assertThat(store.claim(key, hold)).isTrue();
        assertThat(store.claim(key, hold)).as("held still").isFalse();

        Awaitility.await().atMost(Duration.ofSeconds(3)).pollInterval(Duration.ofMillis(50))
                .until(() -> store.claim(key, hold));
    }

    @Test
    @DisplayName("a released claim can be taken at once, and other keys are apart")
    void aReleasedClaimIsFree() {
        StepUpOptionsStore store = store();
        String released = key();
        String kept = key();
        assertThat(store.claim(released, Duration.ofMinutes(1))).isTrue();
        assertThat(store.claim(kept, Duration.ofMinutes(1))).isTrue();

        store.release(released);

        assertThat(store.claim(released, Duration.ofMinutes(1))).isTrue();
        assertThat(store.claim(kept, Duration.ofMinutes(1))).isFalse();
    }

    @Test
    @DisplayName("releasing a claim nobody holds changes nothing")
    void releasingNothingChangesNothing() {
        StepUpOptionsStore store = store();
        String key = key();

        store.release(key);

        assertThat(store.claim(key, Duration.ofMinutes(1))).isTrue();
    }

    @RepeatedTest(25)
    @DisplayName("twenty callers at once: exactly one gets the claim")
    void oneWinnerAmongCallersAtOnce() throws Exception {
        StepUpOptionsStore store = store();
        String key = key();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService callers = Executors.newFixedThreadPool(CALLERS);
        try {
            List<Future<Boolean>> answers = new ArrayList<>();
            for (int i = 0; i < CALLERS; i++) {
                answers.add(callers.submit(() -> {
                    start.await();
                    return store.claim(key, Duration.ofMinutes(1));
                }));
            }
            start.countDown();

            int winners = 0;
            for (Future<Boolean> answer : answers) {
                winners += answer.get() ? 1 : 0;
            }
            assertThat(winners).isEqualTo(1);
        } finally {
            callers.shutdownNow();
        }
    }
}
