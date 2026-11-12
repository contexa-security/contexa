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
package io.contexa.contexacommon.store;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * The same failure, told once and then counted (PR-200). A store that stays away fails every request the same way; a
 * line with its stack for each of them fills the application's log and its disk and says nothing the first did not. The
 * first failure is due a line at once, and after it one line a minute that speaks for the failures since.
 */
public final class RepeatedFailure {

    private static final long REPORT_INTERVAL_NANOS = Duration.ofMinutes(1).toNanos();

    private final LongSupplier nanoClock;
    private final AtomicLong unreported = new AtomicLong();
    private final AtomicLong reportedAt;

    public RepeatedFailure() {
        this(System::nanoTime);
    }

    RepeatedFailure(LongSupplier nanoClock) {
        this.nanoClock = nanoClock;
        this.reportedAt = new AtomicLong(nanoClock.getAsLong() - REPORT_INTERVAL_NANOS);
    }

    /**
     * Counts one failure.
     *
     * @return how many failures the line that is due now speaks for, 0 when no line is due
     */
    public long count() {
        unreported.incrementAndGet();
        long now = nanoClock.getAsLong();
        long last = reportedAt.get();
        if (now - last < REPORT_INTERVAL_NANOS || !reportedAt.compareAndSet(last, now)) {
            return 0L;
        }
        return unreported.getAndSet(0L);
    }
}
