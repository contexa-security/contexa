package io.contexa.showcase.workload.contexa.template;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * N-RUNLEARN-1: a snapshot waits until the engine's learning post process executor is idle, so the decision documents
 * of the user's last requests, stored there after their decision is enforced, are in the snapshot.
 */
class PostProcessSettleTest {

    /** Shaped as the engine's executor (securityLearningPostProcessExecutor). */
    private final ThreadPoolExecutor executor = new ThreadPoolExecutor(2, 4, 60L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(1000));

    @AfterEach
    void shutDown() {
        executor.shutdownNow();
    }

    @Test
    void theSnapshotWaitsForTheDocumentStoredAfterTheLastDecision() {
        AtomicBoolean stored = new AtomicBoolean();
        executor.execute(() -> {
            pause(300);
            stored.set(true);
        });

        boolean settled = new PostProcessSettle(executor, Duration.ofSeconds(5), Duration.ofMillis(100)).await();

        assertThat(settled).isTrue();
        assertThat(stored).isTrue();
    }

    @Test
    void aStoreThatDoesNotEndIsWaitedForOnlyUpToTheLimit() {
        CountDownLatch release = new CountDownLatch(1);
        executor.execute(() -> {
            try {
                release.await();
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        long started = System.nanoTime();

        boolean settled = new PostProcessSettle(executor, Duration.ofMillis(300), Duration.ofMillis(100)).await();

        assertThat(settled).isFalse();
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isGreaterThanOrEqualTo(Duration.ofMillis(300));
        release.countDown();
    }

    @Test
    void anExecutorWhoseWorkCannotBeSeenIsNotWaitedFor() {
        assertThat(new PostProcessSettle(Runnable::run, Duration.ofSeconds(5), Duration.ofMillis(100)).await()).isTrue();
    }

    private static void pause(long millis) {
        try {
            Thread.sleep(millis);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
