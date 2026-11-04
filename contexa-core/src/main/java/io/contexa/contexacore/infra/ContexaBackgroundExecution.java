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
package io.contexa.contexacore.infra;

import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Where Contexa's blocking background work runs. {@code ForkJoinPool.commonPool()} and {@code Schedulers.boundedElastic()}
 * belong to the whole JVM: a call to a slow model held a thread of the application's own parallel streams and reactive
 * work for as long as the model took. These pools hold threads only while there is work, and only daemon ones, so they
 * cost an idle application nothing and never keep its JVM alive.
 */
public final class ContexaBackgroundExecution {

    private static final int IDLE_SECONDS = 60;

    private ContexaBackgroundExecution() {
    }

    /** For {@code subscribeOn} and delays of Contexa's reactive calls. */
    public static Scheduler scheduler() {
        return Pools.SCHEDULER;
    }

    /** For Contexa's {@code CompletableFuture} work. */
    public static ExecutorService executor() {
        return Pools.EXECUTOR;
    }

    /** Created on the first use: an application where Contexa does nothing never pays for them. */
    private static final class Pools {

        private static final Scheduler SCHEDULER = Schedulers.newBoundedElastic(
                Schedulers.DEFAULT_BOUNDED_ELASTIC_SIZE, Schedulers.DEFAULT_BOUNDED_ELASTIC_QUEUESIZE,
                "contexa-blocking", IDLE_SECONDS, true);

        private static final ExecutorService EXECUTOR = executor();

        private static ExecutorService executor() {
            int size = Math.max(4, Runtime.getRuntime().availableProcessors());
            ThreadPoolExecutor pool = new ThreadPoolExecutor(size, size, IDLE_SECONDS, TimeUnit.SECONDS,
                    new LinkedBlockingQueue<>(), daemonThreads());
            pool.allowCoreThreadTimeOut(true);
            return pool;
        }

        private static ThreadFactory daemonThreads() {
            AtomicInteger number = new AtomicInteger();
            return task -> {
                Thread thread = new Thread(task, "contexa-background-" + number.incrementAndGet());
                thread.setDaemon(true);
                return thread;
            };
        }
    }
}
