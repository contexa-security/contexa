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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.contexa.contexacore.util;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Lets a recurring error condition be logged on its first occurrence and then at most once
 * per interval, reporting how many occurrences were not logged in between.
 */
public final class ErrorLogThrottle {

    public static final long SUPPRESSED = -1L;

    private static final long NEVER = Long.MIN_VALUE;

    private final long intervalMs;
    private final LongSupplier currentTimeMillis;
    private final AtomicLong lastLoggedAt = new AtomicLong(NEVER);
    private final AtomicLong suppressedSinceLastLog = new AtomicLong();

    public ErrorLogThrottle(Duration interval) {
        this(interval, System::currentTimeMillis);
    }

    public ErrorLogThrottle(Duration interval, LongSupplier currentTimeMillis) {
        Objects.requireNonNull(interval, "interval");
        this.intervalMs = Math.max(0L, interval.toMillis());
        this.currentTimeMillis = Objects.requireNonNull(currentTimeMillis, "currentTimeMillis");
    }

    /**
     * Returns the number of occurrences skipped since the previous permitted log when this
     * occurrence should be logged, or {@link #SUPPRESSED} when it should not be logged.
     */
    public long tryAcquire() {
        long now = currentTimeMillis.getAsLong();
        long last = lastLoggedAt.get();
        if (last != NEVER && now - last < intervalMs) {
            suppressedSinceLastLog.incrementAndGet();
            return SUPPRESSED;
        }
        if (!lastLoggedAt.compareAndSet(last, now)) {
            suppressedSinceLastLog.incrementAndGet();
            return SUPPRESSED;
        }
        return suppressedSinceLastLog.getAndSet(0L);
    }
}
