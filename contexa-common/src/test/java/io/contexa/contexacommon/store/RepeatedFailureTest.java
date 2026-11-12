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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/** PR-200: a failure that repeats is told once and then counted, a line a minute. */
class RepeatedFailureTest {

    private final AtomicLong clock = new AtomicLong(Duration.ofHours(3).toNanos());
    private final RepeatedFailure failures = new RepeatedFailure(clock::get);

    @Test
    @DisplayName("the first failure is due a line at once, the ones within the minute are not")
    void theFirstFailureIsToldAtOnce() {
        assertThat(failures.count()).isEqualTo(1L);

        for (int failure = 0; failure < 1000; failure++) {
            clock.addAndGet(Duration.ofMillis(50).toNanos());
            assertThat(failures.count()).isZero();
        }
    }

    @Test
    @DisplayName("a minute on, one line speaks for every failure since the last")
    void aMinuteOnTheLineSpeaksForTheFailuresSince() {
        failures.count();
        for (int failure = 0; failure < 41; failure++) {
            failures.count();
        }

        clock.addAndGet(Duration.ofMinutes(1).toNanos());

        assertThat(failures.count()).isEqualTo(42L);
        assertThat(failures.count()).isZero();
    }

    @Test
    @DisplayName("an outage that comes back long after is told at once again")
    void aLaterOutageIsToldAtOnceAgain() {
        failures.count();

        clock.addAndGet(Duration.ofHours(2).toNanos());

        assertThat(failures.count()).isEqualTo(1L);
    }

    @Test
    @DisplayName("threads that fail together lose no failure and share one line")
    void threadsThatFailTogetherShareOneLine() throws InterruptedException {
        int threads = 8;
        int each = 5000;
        AtomicLong lines = new AtomicLong();
        AtomicLong spokenFor = new AtomicLong();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService workers = Executors.newFixedThreadPool(threads);
        try {
            for (int worker = 0; worker < threads; worker++) {
                workers.execute(() -> {
                    try {
                        start.await();
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    for (int failure = 0; failure < each; failure++) {
                        long due = failures.count();
                        if (due > 0) {
                            lines.incrementAndGet();
                            spokenFor.addAndGet(due);
                        }
                    }
                });
            }
            start.countDown();
        } finally {
            workers.shutdown();
        }
        assertThat(workers.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        assertThat(lines.get()).isEqualTo(1L);

        clock.addAndGet(Duration.ofMinutes(1).toNanos());

        assertThat(spokenFor.get() + failures.count()).isEqualTo(threads * (long) each + 1L);
    }
}
