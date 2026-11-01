/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacore.autonomous.store.InMemoryStateSweeper;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Z-16 (N-1): the windows expire as the Redis keys do, an ended one reading as absent at once; the shared sweep
 * ({@link InMemoryStateSweeper}, every minute) releases the memory of the ended ones, without any further request.
 */
class InMemoryProtectableRapidReentryRepositoryExpiryTest {

    @Test
    void expiredUniqueRequestsAreReclaimedByTheSweepWithoutAnyFurtherRequest() {
        MutableClock clock = new MutableClock();
        InMemoryProtectableRapidReentryRepository repository = new InMemoryProtectableRapidReentryRepository(clock);
        InMemoryStateSweeper sweeper = new InMemoryStateSweeper(() -> List.of(repository), Duration.ofDays(1));
        try {
            for (int i = 0; i < 200; i++) {
                assertThat(repository.tryAcquire("user", "binding", "request-" + i, Duration.ofMillis(50))).isTrue();
            }
            clock.advance(Duration.ofMillis(60));
            assertThat(repository.heldWindows()).as("released by the sweep, not by a thread of its own").isEqualTo(200);

            sweeper.sweep();

            assertThat(repository.heldWindows()).isZero();
        } finally {
            sweeper.close();
            repository.close();
        }
    }

    @Test
    void repeatedUniqueRequestBatchesDoNotAccumulateExpiredEntries() {
        MutableClock clock = new MutableClock();
        try (InMemoryProtectableRapidReentryRepository repository = controlledRepository(clock)) {
            for (int batch = 0; batch < 4; batch++) {
                for (int i = 0; i < 500; i++) {
                    repository.tryAcquire("user", "binding", "request-" + batch + "-" + i, Duration.ofSeconds(5));
                }
                assertThat(repository.heldWindows()).isEqualTo(500);
                clock.advance(Duration.ofSeconds(6));
                repository.removeExpiredEntries();
                assertThat(repository.heldWindows()).isZero();
            }
        }
    }

    @Test
    void onlyOneConcurrentAcquireSucceedsWithinTheWindow() throws Exception {
        ExecutorService requests = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        try (InMemoryProtectableRapidReentryRepository repository = controlledRepository(new MutableClock())) {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 32; i++) {
                results.add(requests.submit(() -> {
                    awaitLatch(start);
                    return repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5));
                }));
            }
            start.countDown();
            int successful = 0;
            for (Future<Boolean> result : results) {
                if (result.get(5, TimeUnit.SECONDS)) {
                    successful++;
                }
            }
            assertThat(successful).isEqualTo(1);
            assertThat(repository.heldWindows()).isEqualTo(1);
        } finally {
            start.countDown();
            requests.shutdownNow();
        }
    }

    @Test
    void cleanupPreservesLiveWindowsAndAllowsReacquisitionAfterExpiry() {
        MutableClock clock = new MutableClock();
        try (InMemoryProtectableRapidReentryRepository repository = controlledRepository(clock)) {
            assertThat(repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5))).isTrue();
            clock.advance(Duration.ofSeconds(4));
            repository.removeExpiredEntries();
            assertThat(repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5))).isFalse();
            clock.advance(Duration.ofSeconds(1));
            repository.removeExpiredEntries();
            assertThat(repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5))).isTrue();
            assertThat(repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5))).isFalse();
        }
    }

    @Test
    void anEndedWindowIsTakenAgainBeforeTheSweepReleasesIt() {
        MutableClock clock = new MutableClock();
        try (InMemoryProtectableRapidReentryRepository repository = controlledRepository(clock)) {
            assertThat(repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5))).isTrue();
            clock.advance(Duration.ofSeconds(5));

            assertThat(repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5))).isTrue();
            assertThat(repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5))).isFalse();
            assertThat(repository.heldWindows()).isEqualTo(1);
        }
    }

    @Test
    void aSweepRacingAReacquisitionNeverDeletesTheNewWindow() throws Exception {
        MutableClock clock = new MutableClock();
        ExecutorService racers = Executors.newFixedThreadPool(2);
        try (InMemoryProtectableRapidReentryRepository repository = controlledRepository(clock)) {
            for (int round = 0; round < 500; round++) {
                String request = "request-" + round;
                repository.tryAcquire("user", "binding", request, Duration.ofSeconds(5));
                clock.advance(Duration.ofSeconds(6));
                CountDownLatch start = new CountDownLatch(1);
                Future<?> sweep = racers.submit(() -> {
                    awaitLatch(start);
                    repository.removeExpiredEntries();
                });
                Future<Boolean> reacquired = racers.submit(() -> {
                    awaitLatch(start);
                    return repository.tryAcquire("user", "binding", request, Duration.ofSeconds(5));
                });
                start.countDown();
                sweep.get(5, TimeUnit.SECONDS);

                assertThat(reacquired.get(5, TimeUnit.SECONDS)).as(request).isTrue();
                assertThat(repository.tryAcquire("user", "binding", request, Duration.ofSeconds(5)))
                        .as("the window taken again stays: %s", request).isFalse();
            }
        } finally {
            racers.shutdownNow();
        }
    }

    @Test
    void closingTheSpringContextReleasesRetainedEntriesAndNoCleanupThreadIsLeft() {
        InMemoryProtectableRapidReentryRepository repository;
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.registerBean(InMemoryProtectableRapidReentryRepository.class,
                    () -> new InMemoryProtectableRapidReentryRepository());
            context.refresh();
            repository = context.getBean(InMemoryProtectableRapidReentryRepository.class);
            for (int i = 0; i < 100; i++) {
                repository.tryAcquire("user", "binding", "request-" + i, Duration.ofHours(1));
            }
            assertThat(repository.heldWindows()).isEqualTo(100);
            assertThat(Thread.getAllStackTraces().keySet())
                    .noneMatch(thread -> thread.getName().equals("contexa-protectable-reentry-cleanup"));
        }
        assertThat(repository.heldWindows()).isZero();
    }

    private InMemoryProtectableRapidReentryRepository controlledRepository(Clock clock) {
        return new InMemoryProtectableRapidReentryRepository(clock);
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            assertThat(latch.await(5, TimeUnit.SECONDS)).as("coordinated operation must reach its boundary").isTrue();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError(exception);
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-09-23T00:00:00Z"));

        void advance(Duration duration) {
            now.updateAndGet(value -> value.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }
}
