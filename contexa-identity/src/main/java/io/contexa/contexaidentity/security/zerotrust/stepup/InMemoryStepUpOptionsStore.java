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
package io.contexa.contexaidentity.security.zerotrust.stepup;

import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import org.springframework.lang.Nullable;

import java.io.Serializable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** The step-up options of one application instance (standalone), with the same expiry as the Redis store. */
public class InMemoryStepUpOptionsStore implements StepUpOptionsStore, ExpiringStateStore {

    private record Entry(Serializable value, Instant expiresAt) {
    }

    private static final String CLAIM_PREFIX = "claim:";
    private static final String COUNT_PREFIX = "count:";

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryStepUpOptionsStore() {
        this(Clock.systemUTC());
    }

    InMemoryStepUpOptionsStore(Clock clock) {
        this.clock = clock;
    }

    /**
     * Claims are made for any address asked for and counts for any context that answers, and no put may ever come: the
     * sweep frees them as Redis expires them.
     */
    @Override
    public void removeExpiredEntries() {
        Instant now = clock.instant();
        entries.values().removeIf(entry -> !entry.expiresAt().isAfter(now));
    }

    @Override
    public void put(String key, Serializable value) {
        removeExpiredEntries();
        entries.put(key, new Entry(value, clock.instant().plus(TIME_TO_LIVE)));
    }

    @Override
    public boolean claim(String key, Duration holdFor) {
        Instant now = clock.instant();
        boolean[] claimed = {false};
        entries.compute(CLAIM_PREFIX + key, (k, held) -> {
            if (held != null && held.expiresAt().isAfter(now)) {
                return held;
            }
            claimed[0] = true;
            return new Entry(CLAIM_PREFIX, now.plus(holdFor));
        });
        return claimed[0];
    }

    @Override
    public void release(String key) {
        entries.remove(CLAIM_PREFIX + key);
    }

    @Override
    public long increment(String key, Duration holdFor) {
        Instant now = clock.instant();
        long[] count = {1};
        entries.compute(COUNT_PREFIX + key, (k, held) -> {
            if (held != null && held.expiresAt().isAfter(now)) {
                count[0] = (Long) held.value() + 1;
                return new Entry(count[0], held.expiresAt());
            }
            return new Entry(count[0], now.plus(holdFor));
        });
        return count[0];
    }

    @Override
    public void clearCount(String key) {
        entries.remove(COUNT_PREFIX + key);
    }

    @Override
    public boolean holds(String key) {
        Entry entry = entries.get(key);
        return entry != null && entry.expiresAt().isAfter(clock.instant());
    }

    @Override
    @Nullable
    public <T extends Serializable> T take(String key, Class<T> type) {
        Entry entry = entries.remove(key);
        if (entry == null || !entry.expiresAt().isAfter(clock.instant()) || !type.isInstance(entry.value())) {
            return null;
        }
        return type.cast(entry.value());
    }
}
