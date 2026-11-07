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
package io.contexa.contexacommon.security.bridge.runtime;

import io.contexa.contexacommon.store.StoreGate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.lang.Nullable;

import java.sql.SQLTransientConnectionException;
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * Keeps the application's request thread from waiting on Contexa's own database. What Contexa reads there for a request
 * only adds to the request, and the callers already go on without it; an outage of that database must cost the
 * application a moment, not its threads. The pool's own wait (60 seconds by default) stays as it is, because the engine's
 * long work relies on it, so the wait is bounded here, on the request path only, and whatever the outage looks like: a
 * refused connection, a pool that is used up, or a connection that never answers.
 * <p>
 * The work runs on a small pool of daemon workers that exist only while they are needed. A worker that outlives the wait
 * finishes on its own, so the database coming back needs no action. While every worker is held by work whose request has
 * stopped waiting, a request does not wait at all. A crowd of requests that finds the workers busy with work that is still
 * within its wait (a database that answers, asked by more requests at once than there are workers) is not an outage: its work
 * waits in a short line, inside the same wait, and is withdrawn when the wait ends. The work must not depend on what is bound
 * to the request thread.
 */
@Slf4j
public final class RequestPathDatabaseGuard implements DisposableBean {

    private static final Duration DEFAULT_WAIT = Duration.ofSeconds(1);
    private static final int DEFAULT_WORKERS = 32;
    /** Work waiting for a worker, for each worker: a request thread of the application holds one place at most. */
    private static final int LINE_PER_WORKER = 16;
    private static final long WORKER_IDLE_SECONDS = 30L;
    private static final long REPORT_INTERVAL_MILLIS = 60_000L;

    private final long waitNanos;
    private final int maximumWorkers;
    private final ThreadPoolExecutor workers;
    /** The workers that are running work whose request has stopped waiting: the measure of an outage. */
    private final AtomicInteger overdue = new AtomicInteger();
    private final AtomicLong skipped = new AtomicLong();
    private final AtomicLong lastReport = new AtomicLong();
    @Nullable
    private final StoreGate gate;

    public RequestPathDatabaseGuard() {
        this(DEFAULT_WAIT, DEFAULT_WORKERS);
    }

    /** A gate that is down answers at once, and a wait that ends without an answer lowers it. */
    public RequestPathDatabaseGuard(@Nullable StoreGate gate) {
        this(DEFAULT_WAIT, DEFAULT_WORKERS, gate);
    }

    public RequestPathDatabaseGuard(Duration wait, int maximumWorkers) {
        this(wait, maximumWorkers, null);
    }

    RequestPathDatabaseGuard(Duration wait, int maximumWorkers, @Nullable StoreGate gate) {
        this.gate = gate;
        this.waitNanos = wait.toNanos();
        this.maximumWorkers = Math.max(1, maximumWorkers);
        AtomicInteger number = new AtomicInteger();
        this.workers = new ThreadPoolExecutor(this.maximumWorkers, this.maximumWorkers, WORKER_IDLE_SECONDS, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(this.maximumWorkers * LINE_PER_WORKER), work -> {
            Thread thread = new Thread(work, "contexa-request-database-" + number.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
        // the workers exist only while they are needed
        this.workers.allowCoreThreadTimeOut(true);
    }

    /** What happens to one piece of work: waiting for a worker, running, done, given up on while running, or withdrawn before it ran. */
    private static final int QUEUED = 0;
    private static final int RUNNING = 1;
    private static final int DONE = 2;
    private static final int ABANDONED = 3;
    private static final int WITHDRAWN = 4;

    private final class Work<T> implements Callable<T> {
        private final Supplier<T> work;
        private final AtomicInteger state = new AtomicInteger(QUEUED);

        private Work(Supplier<T> work) {
            this.work = work;
        }

        @Override
        public T call() {
            if (!state.compareAndSet(QUEUED, RUNNING)) {
                return null;                       // withdrawn while it waited for a worker
            }
            try {
                return work.get();
            } finally {
                if (!state.compareAndSet(RUNNING, DONE)) {
                    overdue.decrementAndGet();      // its request had stopped waiting: the worker is free again
                }
            }
        }

        /** The request stops waiting: work that has not begun is withdrawn, work that is running is counted as overdue until it ends. */
        private void giveUp(Future<T> answer) {
            if (state.compareAndSet(QUEUED, WITHDRAWN)) {
                answer.cancel(false);
                workers.getQueue().remove(answer);
            }
            else if (state.compareAndSet(RUNNING, ABANDONED)) {
                overdue.incrementAndGet();
            }
        }
    }

    /**
     * The answer of the work, or {@code whenUnavailable} when it does not come in time. A failure of the work reaches the
     * caller as it would have without this guard.
     */
    public <T> T call(Supplier<T> work, T whenUnavailable) {
        if (gate != null && gate.isDown()) {
            report();
            return whenUnavailable;
        }
        if (overdue.get() >= maximumWorkers) {
            // every worker is held by work that outlived its wait: the database does not answer, and a request does not wait for it
            report();
            return whenUnavailable;
        }
        Work<T> task = new Work<>(work);
        Future<T> answer;
        try {
            answer = workers.submit(task);
        } catch (RejectedExecutionException lineFull) {
            report();
            return whenUnavailable;
        }
        try {
            return answer.get(waitNanos, TimeUnit.NANOSECONDS);
        } catch (TimeoutException late) {
            task.giveUp(answer);
            report();
            if (gate != null) {
                gate.fail(new SQLTransientConnectionException("No answer within the request's wait", late));
            }
            return whenUnavailable;
        } catch (InterruptedException interrupted) {
            task.giveUp(answer);
            Thread.currentThread().interrupt();
            return whenUnavailable;
        } catch (ExecutionException failed) {
            if (failed.getCause() instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (failed.getCause() instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException(failed.getCause());
        }
    }

    private void report() {
        long now = System.currentTimeMillis();
        long count = skipped.incrementAndGet();
        long last = lastReport.get();
        if (now - last >= REPORT_INTERVAL_MILLIS && lastReport.compareAndSet(last, now)) {
            log.warn("Contexa's database did not answer in time; the application's requests go on without what Contexa reads there ({} so far)", count);
        }
    }

    @Override
    public void destroy() {
        workers.shutdownNow();
    }
}
