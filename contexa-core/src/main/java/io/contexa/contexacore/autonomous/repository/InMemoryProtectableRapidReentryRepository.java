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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;

import java.time.Clock;
import java.time.Duration;

/**
 * In-memory rapid re-entry windows. Z-16 (N-1): each window is a key of an {@link ExpiringKeySpace} that lasts the
 * window, taken only while none is in force as the Redis store sets its key (SET NX PX); an ended window reads as
 * absent, and the sweep ({@code InMemoryStateSweeper}) releases the ended ones.
 */
public class InMemoryProtectableRapidReentryRepository
        implements ProtectableRapidReentryRepository, ExpiringStateStore, AutoCloseable {

    private static final String KEY_PART_SEPARATOR = Character.toString(0);

    private final ExpiringKeySpace<Boolean> reentryWindows;

    public InMemoryProtectableRapidReentryRepository() {
        this(Clock.systemUTC());
    }

    /** Measures the windows with {@code clock}. */
    InMemoryProtectableRapidReentryRepository(Clock clock) {
        this.reentryWindows = ExpiringKeySpace.<Boolean>builder(clock).build();
    }

    @Override
    public boolean tryAcquire(String userId, String contextBindingHash, String resourceKey, Duration window) {
        if (isInvalid(userId) || isInvalid(contextBindingHash) || isInvalid(resourceKey) || window == null) {
            return true;
        }

        return reentryWindows.putIfAbsent(buildKey(userId, contextBindingHash, resourceKey), Boolean.TRUE, window);
    }

    @Override
    public void removeExpiredEntries() {
        reentryWindows.removeExpired();
    }

    /** Releases every window. */
    @Override
    public void close() {
        reentryWindows.removeIf(key -> true);
    }

    /** How many windows take memory, ended ones the sweep has not released yet included. */
    int heldWindows() {
        return reentryWindows.size();
    }

    private String buildKey(String userId, String contextBindingHash, String resourceKey) {
        return userId + KEY_PART_SEPARATOR + contextBindingHash + KEY_PART_SEPARATOR + resourceKey;
    }

    private boolean isInvalid(String value) {
        return value == null || value.isBlank();
    }
}
