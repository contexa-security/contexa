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
package io.contexa.contexacommon.store;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContexaWorkCallerRunsPolicyTest {

    private final CountDownLatch release = new CountDownLatch(1);
    private ThreadPoolExecutor executor;

    @BeforeEach
    void saturate() throws InterruptedException {
        executor = new ThreadPoolExecutor(1, 1, 60L, TimeUnit.SECONDS, new SynchronousQueue<>(),
                new ContexaWorkCallerRunsPolicy());
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
    @DisplayName("work a full pool turned away runs on the thread that handed it over, as Contexa's own work")
    void workTurnedAwayRunsOnTheCallerAsContexasOwnWork() {
        AtomicReference<Thread> ranOn = new AtomicReference<>();
        AtomicBoolean inContexaWork = new AtomicBoolean();

        executor.execute(() -> {
            ranOn.set(Thread.currentThread());
            inContexaWork.set(RequestPathScope.inContexaWork());
        });

        assertThat(ranOn.get()).isSameAs(Thread.currentThread());
        assertThat(inContexaWork).isTrue();
        assertThat(RequestPathScope.inContexaWork()).isFalse();
    }

    @Test
    @DisplayName("work that fails leaves the thread out of Contexa's own work")
    void workThatFailsLeavesTheThreadOutOfContexasOwnWork() {
        assertThatThrownBy(() -> executor.execute(() -> {
            throw new IllegalStateException("a bug");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(RequestPathScope.inContexaWork()).isFalse();
    }

    @Test
    @DisplayName("a thread already in Contexa's own work is still in it after the work that was turned away")
    void aThreadAlreadyInContexasOwnWorkStaysInIt() {
        RequestPathScope.enter();
        try {
            executor.execute(() -> {
            });

            assertThat(RequestPathScope.inContexaWork()).isTrue();
        } finally {
            RequestPathScope.leave();
        }
        assertThat(RequestPathScope.inContexaWork()).isFalse();
    }

    @Test
    @DisplayName("work handed over after the shutdown is discarded")
    void afterTheShutdownTheWorkIsDiscarded() {
        executor.shutdown();
        AtomicBoolean ran = new AtomicBoolean();

        executor.execute(() -> ran.set(true));

        assertThat(ran).isFalse();
    }
}
