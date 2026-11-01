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
package io.contexa.contexacore.std.rag.service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** A retry scheduler a test drives by hand: a scheduled task runs when the test says so, never on its own. */
final class ManualRetryScheduler implements FailedDocumentRetrier.Scheduler {

    /** The delay of every task that was scheduled, in order. */
    final List<Duration> delays = new ArrayList<>();
    boolean shutDown;
    private Runnable pending;

    @Override
    public void schedule(Runnable task, Duration delay) {
        if (pending != null) {
            throw new IllegalStateException("a second retry was scheduled while one is waiting");
        }
        pending = task;
        delays.add(delay);
    }

    @Override
    public void shutdown() {
        shutDown = true;
        pending = null;
    }

    boolean hasPending() {
        return pending != null;
    }

    /** Runs the waiting task once, as the scheduler thread would when its delay has passed. */
    void runPending() {
        Runnable task = pending;
        if (task == null) {
            throw new IllegalStateException("no retry is scheduled");
        }
        pending = null;
        task.run();
    }

    /** Runs scheduled tasks until none waits; the limit stops a retry that never ends. */
    int runUntilIdle(int limit) {
        int runs = 0;
        while (pending != null) {
            if (runs >= limit) {
                throw new IllegalStateException("the retry did not end within " + limit + " runs");
            }
            runPending();
            runs++;
        }
        return runs;
    }
}
