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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The line the session records of requests are made in, off the thread of the request. The records of one session go
 * through one thread in the order they were asked for (the session's narrative is a list the records are appended to),
 * and sessions are spread over a few threads. A line that is full, or stopped, loses no record: the thread that asks
 * makes it, as it did before the line existed, and the request then waits for it like any other work it does itself.
 * A thread with nothing to record is given back after a minute.
 */
@Slf4j
public final class SessionRecordingLine implements DisposableBean {

    private static final long IDLE_SECONDS = 60L;
    private static final long STOP_WAIT_SECONDS = 10L;

    private final ThreadPoolExecutor[] threads;
    private final AtomicInteger full = new AtomicInteger();

    /**
     * @param threads   how many threads record, one session always on the same one
     * @param queueSize how many records wait for each thread before the asking thread makes the record itself
     */
    public SessionRecordingLine(int threads, int queueSize) {
        int count = Math.max(1, threads);
        int size = Math.max(1, queueSize);
        this.threads = new ThreadPoolExecutor[count];
        AtomicInteger names = new AtomicInteger();
        RejectedExecutionHandler askingThreadMakes = (work, line) -> {
            full.incrementAndGet();
            work.run();
        };
        for (int index = 0; index < count; index++) {
            ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, IDLE_SECONDS, TimeUnit.SECONDS,
                    new ArrayBlockingQueue<>(size), work -> {
                Thread thread = new Thread(work, "contexa-session-record-" + names.incrementAndGet());
                thread.setDaemon(true);
                return thread;
            }, askingThreadMakes);
            executor.allowCoreThreadTimeOut(true);
            this.threads[index] = executor;
        }
    }

    /** Makes the record off this thread, after the records of the key that were asked for before it. */
    public void run(String key, Runnable work) {
        int index = Math.floorMod(key == null ? 0 : key.hashCode(), threads.length);
        threads[index].execute(work);
    }

    /** How many records the asking thread made itself because the line was full or stopped. */
    public int madeByTheAskingThread() {
        return full.get();
    }

    @Override
    public void destroy() {
        for (ThreadPoolExecutor executor : threads) {
            executor.shutdown();
        }
        for (ThreadPoolExecutor executor : threads) {
            try {
                if (!executor.awaitTermination(STOP_WAIT_SECONDS, TimeUnit.SECONDS)) {
                    log.error("[SessionRecordingLine] Records were still being made when the line was stopped");
                    executor.shutdownNow();
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                executor.shutdownNow();
            }
        }
    }
}
