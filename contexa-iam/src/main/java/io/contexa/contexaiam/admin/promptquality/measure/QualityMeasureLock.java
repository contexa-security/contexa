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
package io.contexa.contexaiam.admin.promptquality.measure;

import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.core.SimpleLock;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The lock that lets one server at a time run the measurements of the prompt quality (quality plan 3.3, 9): the gate
 * of a model server is kept on each server, so measurements of two servers would not wait behind each other. The lock
 * is held for a while and extended while the measurement runs; a server that stops lets it run out, and another
 * server takes it and resumes the measurement.
 */
public interface QualityMeasureLock {

    /** The lock, held until it is released or runs out. */
    interface Held {

        /** Holds it for that long from now; false when it ran out meanwhile and is not this server's any more. */
        boolean extend(Duration atMostFor);

        void release();
    }

    /** The lock, held for at most that long, or empty when another server holds it. */
    Optional<Held> acquire(Duration atMostFor);

    /**
     * The lock of the store the scheduled work of Contexa takes (ShedLock, {@code ctxa_shedlock}), shared by the
     * servers of one database.
     */
    static QualityMeasureLock shedLock(LockProvider provider, String name, Clock clock) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(name, "name");
        Clock time = clock != null ? clock : Clock.systemUTC();
        return atMostFor -> provider.lock(new LockConfiguration(time.instant(), name, atMostFor, Duration.ZERO))
                .map(lock -> {
                    AtomicReference<SimpleLock> current = new AtomicReference<>(lock);
                    return new Held() {
                        @Override
                        public boolean extend(Duration longer) {
                            SimpleLock held = current.get();
                            if (held == null) {
                                return false;
                            }
                            Optional<SimpleLock> extended = held.extend(longer, Duration.ZERO);
                            current.set(extended.orElse(null));
                            return extended.isPresent();
                        }

                        @Override
                        public void release() {
                            SimpleLock held = current.getAndSet(null);
                            if (held != null) {
                                held.unlock();
                            }
                        }
                    };
                });
    }

    /** A lock of this server alone, for an installation without the lock store: one server runs measurements. */
    static QualityMeasureLock local() {
        Semaphore lock = new Semaphore(1);
        return atMostFor -> {
            if (!lock.tryAcquire()) {
                return Optional.empty();
            }
            return Optional.of(new Held() {
                private final AtomicBoolean held = new AtomicBoolean(true);

                @Override
                public boolean extend(Duration longer) {
                    return held.get();
                }

                @Override
                public void release() {
                    if (held.compareAndSet(true, false)) {
                        lock.release();
                    }
                }
            });
        };
    }
}
