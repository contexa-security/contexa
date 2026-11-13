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
package io.contexa.contexacommon.cache;

import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Caffeine's builder with the maintenance of the cache (eviction, expiry, removal listeners) on a pool of Contexa's own.
 * <p>
 * Caffeine runs that work on the common fork-join pool unless it is told otherwise, and that pool belongs to the whole JVM:
 * it serves the application's own parallel streams and {@code CompletableFuture}s. A cache of Contexa that grows or expires must not
 * take a thread of it. The pool holds threads only while there is work, and only daemon ones, so it costs an idle application nothing
 * and never keeps its JVM alive. Every cache of Contexa is built through this method.
 */
public final class ContexaCaffeine {

    private static final int IDLE_SECONDS = 60;
    private static final int THREADS = 2;

    private ContexaCaffeine() {
    }

    public static Caffeine<Object, Object> newBuilder() {
        return Caffeine.newBuilder().executor(Maintenance.EXECUTOR);
    }

    /** Created on the first cache: an application where Contexa builds none never pays for it. */
    private static final class Maintenance {

        private static final ExecutorService EXECUTOR = executor();

        private static ExecutorService executor() {
            ThreadPoolExecutor pool = new ThreadPoolExecutor(THREADS, THREADS, IDLE_SECONDS, TimeUnit.SECONDS, new LinkedBlockingQueue<>(), daemonThreads());
            pool.allowCoreThreadTimeOut(true);
            return pool;
        }

        private static ThreadFactory daemonThreads() {
            AtomicInteger number = new AtomicInteger();
            return task -> {
                Thread thread = new Thread(task, "contexa-cache-maintenance-" + number.incrementAndGet());
                thread.setDaemon(true);
                return thread;
            };
        }
    }
}
