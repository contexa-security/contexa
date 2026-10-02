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

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.mock;

class InMemoryProtectableRapidReentryRepositoryExpiryTest {

    @Test
    void expiredUniqueRequestsAreReclaimedWithoutAnyFurtherRequest() {
        try (InMemoryProtectableRapidReentryRepository repository = new InMemoryProtectableRapidReentryRepository()) {
            for (int i = 0; i < 200; i++) {
                assertThat(repository.tryAcquire("user", "binding", "request-" + i, Duration.ofMillis(50))).isTrue();
            }
            // Inspect physical retention only; do not trigger cleanup by looking up request keys.
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(entries(repository)).isEmpty());
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
                assertThat(entries(repository)).hasSize(500);
                clock.advance(Duration.ofSeconds(6));
                repository.removeExpiredEntries();
                assertThat(entries(repository)).isEmpty();
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
            assertThat(entries(repository)).hasSize(1);
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
    void delayedExpiryRemovalCannotDeleteAReacquiredWindow() throws Exception {
        MutableClock clock = new MutableClock();
        BlockingRemovalMap map = new BlockingRemovalMap();
        ExecutorService cleanup = Executors.newSingleThreadExecutor();
        try (InMemoryProtectableRapidReentryRepository repository = controlledRepository(clock)) {
            ReflectionTestUtils.setField(repository, "reentryWindows", map);
            repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5));
            clock.advance(Duration.ofSeconds(6));
            Future<?> removal = cleanup.submit(() -> {
                map.cleanupThread = Thread.currentThread();
                repository.removeExpiredEntries();
            });
            awaitLatch(map.removalStarted);

            assertThat(repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5))).isTrue();
            map.allowRemoval.countDown();
            removal.get(5, TimeUnit.SECONDS);

            assertThat(repository.tryAcquire("user", "binding", "same-request", Duration.ofSeconds(5))).isFalse();
            assertThat(entries(repository)).hasSize(1);
        } finally {
            map.allowRemoval.countDown();
            cleanup.shutdownNow();
        }
    }

    @Test
    void closingTheSpringContextStopsCleanupAndReleasesRetainedEntries() {
        InMemoryProtectableRapidReentryRepository repository;
        ScheduledExecutorService executor;
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.registerBean(InMemoryProtectableRapidReentryRepository.class,
                    InMemoryProtectableRapidReentryRepository::new);
            context.refresh();
            repository = context.getBean(InMemoryProtectableRapidReentryRepository.class);
            executor = (ScheduledExecutorService) ReflectionTestUtils.getField(repository, "cleanupExecutor");
            for (int i = 0; i < 100; i++) {
                repository.tryAcquire("user", "binding", "request-" + i, Duration.ofHours(1));
            }
            assertThat(executor.isShutdown()).isFalse();
            assertThat(entries(repository)).hasSize(100);
        }
        assertThat(executor.isShutdown()).isTrue();
        await().atMost(Duration.ofSeconds(5)).until(executor::isTerminated);
        assertThat(entries(repository)).isEmpty();
    }

    private InMemoryProtectableRapidReentryRepository controlledRepository(Clock clock) {
        return new InMemoryProtectableRapidReentryRepository(clock, mock(ScheduledExecutorService.class));
    }

    @SuppressWarnings("unchecked")
    private ConcurrentHashMap<String, Instant> entries(InMemoryProtectableRapidReentryRepository repository) {
        return (ConcurrentHashMap<String, Instant>) ReflectionTestUtils.getField(repository, "reentryWindows");
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

    private static final class BlockingRemovalMap extends ConcurrentHashMap<String, Instant> {
        private final CountDownLatch removalStarted = new CountDownLatch(1);
        private final CountDownLatch allowRemoval = new CountDownLatch(1);
        private volatile Thread cleanupThread;

        @Override
        public boolean remove(Object key, Object value) {
            if (Thread.currentThread() == cleanupThread) {
                removalStarted.countDown();
                awaitLatch(allowRemoval);
            }
            return super.remove(key, value);
        }
    }
}
