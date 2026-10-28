package io.contexa.showcase.portal.ops;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/** The harness job queue: one job at a time unless the operator allows more (showcase.ops.job-threads). */
class OpsJobExecutorTest {

    @Test
    void oneThreadRunsTheJobsOneAfterAnother() throws Exception {
        ExecutorService executor = OpsController.jobExecutor(1);
        try {
            AtomicInteger running = new AtomicInteger();
            AtomicInteger mostAtOnce = new AtomicInteger();
            CountDownLatch done = new CountDownLatch(3);
            for (int i = 0; i < 3; i++) {
                executor.submit(() -> {
                    mostAtOnce.accumulateAndGet(running.incrementAndGet(), Math::max);
                    sleep(50);
                    running.decrementAndGet();
                    done.countDown();
                });
            }
            assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(mostAtOnce.get()).isEqualTo(1);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void severalThreadsRunTheJobsAtTheSameTime() throws Exception {
        ExecutorService executor = OpsController.jobExecutor(3);
        try {
            // each job waits for the other two: they finish only when all three run at once
            CountDownLatch together = new CountDownLatch(3);
            CountDownLatch done = new CountDownLatch(3);
            for (int i = 0; i < 3; i++) {
                executor.submit(() -> {
                    together.countDown();
                    try {
                        if (together.await(5, TimeUnit.SECONDS)) {
                            done.countDown();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
            assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void theNumberOfThreadsStaysBetweenOneAndTheLimit() {
        assertThat(poolSize(0)).isEqualTo(1);
        assertThat(poolSize(-4)).isEqualTo(1);
        assertThat(poolSize(6)).isEqualTo(6);
        assertThat(poolSize(500)).isEqualTo(OpsController.MAX_JOB_THREADS);
    }

    private static int poolSize(int requested) {
        ExecutorService executor = OpsController.jobExecutor(requested);
        try {
            return ((ThreadPoolExecutor) executor).getCorePoolSize();
        } finally {
            executor.shutdownNow();
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
