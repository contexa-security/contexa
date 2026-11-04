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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;

import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
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
 * finishes on its own, so the database coming back needs no action; while all of them are held, a request does not wait at
 * all. The work must not depend on what is bound to the request thread.
 */
@Slf4j
public final class RequestPathDatabaseGuard implements DisposableBean {

    private static final Duration DEFAULT_WAIT = Duration.ofSeconds(1);
    private static final int DEFAULT_WORKERS = 32;
    private static final long WORKER_IDLE_SECONDS = 30L;
    private static final long REPORT_INTERVAL_MILLIS = 60_000L;

    private final long waitNanos;
    private final ThreadPoolExecutor workers;
    private final AtomicLong skipped = new AtomicLong();
    private final AtomicLong lastReport = new AtomicLong();

    public RequestPathDatabaseGuard() {
        this(DEFAULT_WAIT, DEFAULT_WORKERS);
    }

    public RequestPathDatabaseGuard(Duration wait, int maximumWorkers) {
        this.waitNanos = wait.toNanos();
        AtomicInteger number = new AtomicInteger();
        this.workers = new ThreadPoolExecutor(0, maximumWorkers, WORKER_IDLE_SECONDS, TimeUnit.SECONDS, new SynchronousQueue<>(), work -> {
            Thread thread = new Thread(work, "contexa-request-database-" + number.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * The answer of the work, or {@code whenUnavailable} when it does not come in time. A failure of the work reaches the
     * caller as it would have without this guard.
     */
    public <T> T call(Supplier<T> work, T whenUnavailable) {
        Future<T> answer;
        try {
            answer = workers.submit(work::get);
        } catch (RejectedExecutionException allHeld) {
            report();
            return whenUnavailable;
        }
        try {
            return answer.get(waitNanos, TimeUnit.NANOSECONDS);
        } catch (TimeoutException late) {
            report();
            return whenUnavailable;
        } catch (InterruptedException interrupted) {
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
