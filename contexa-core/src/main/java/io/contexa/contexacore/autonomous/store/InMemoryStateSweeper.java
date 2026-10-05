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
package io.contexa.contexacore.autonomous.store;

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Periodically removes expired entries from the in-memory stores of a standalone deployment, so long-running
 * processes do not keep every user, session and request they have ever seen.
 */
@Slf4j
public class InMemoryStateSweeper implements AutoCloseable {

    public static final Duration DEFAULT_INTERVAL = Duration.ofMinutes(1);

    private final Supplier<List<ExpiringStateStore>> stores;
    private final ScheduledExecutorService executor;

    public InMemoryStateSweeper(Supplier<List<ExpiringStateStore>> stores, Duration interval) {
        this.stores = stores;
        this.executor = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "contexa-in-memory-state-sweeper");
            thread.setDaemon(true);
            return thread;
        });
        long periodMs = interval.toMillis();
        executor.scheduleWithFixedDelay(this::sweep, periodMs, periodMs, TimeUnit.MILLISECONDS);
    }

    /** Runs one sweep over every store; a failing store does not stop the others. */
    public void sweep() {
        for (ExpiringStateStore store : stores.get()) {
            try {
                store.removeExpiredEntries();
            } catch (RuntimeException e) {
                log.error("[InMemoryStateSweeper] Expired entry removal failed: store={}", store.getClass().getSimpleName(), e);
            }
        }
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }
}
