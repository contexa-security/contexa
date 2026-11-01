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
package io.contexa.contexacore.autonomous.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-25 (b): with no room, a deferrable store is left for later on the caller's thread without running, and any other
 * task runs on the caller as CallerRunsPolicy runs it.
 */
class LearningStoreRejectionPolicyTest {

    private final CountDownLatch release = new CountDownLatch(1);
    private ThreadPoolExecutor executor;

    @BeforeEach
    void saturate() throws InterruptedException {
        executor = new ThreadPoolExecutor(1, 1, 60L, TimeUnit.SECONDS, new SynchronousQueue<>(),
                new LearningStoreRejectionPolicy());
        CountDownLatch started = new CountDownLatch(1);
        executor.execute(() -> {
            started.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();
    }

    @AfterEach
    void stop() throws InterruptedException {
        release.countDown();
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    void aDeferrableStoreIsLeftForLaterWithoutRunning() {
        List<String> done = new ArrayList<>();
        Thread caller = Thread.currentThread();

        executor.execute(LearningStoreRejectionPolicy.deferrable(() -> done.add("stored"),
                () -> done.add(Thread.currentThread() == caller ? "deferred on the caller" : "deferred elsewhere")));

        assertThat(done).containsExactly("deferred on the caller");
    }

    @Test
    void anyOtherTaskRunsOnTheCallerAsBefore() {
        List<String> done = new ArrayList<>();
        Thread caller = Thread.currentThread();

        executor.execute(() -> done.add(Thread.currentThread() == caller ? "ran on the caller" : "ran elsewhere"));

        assertThat(done).containsExactly("ran on the caller");
    }

    @Test
    void afterShutdownAnOtherTaskIsDiscardedAndAStoreIsStillLeftForLater() {
        List<String> done = new ArrayList<>();
        executor.shutdown();

        executor.execute(() -> done.add("ran"));
        executor.execute(LearningStoreRejectionPolicy.deferrable(() -> done.add("stored"), () -> done.add("deferred")));

        assertThat(done).containsExactly("deferred");
    }
}
