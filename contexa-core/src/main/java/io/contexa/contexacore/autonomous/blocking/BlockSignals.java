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
package io.contexa.contexacore.autonomous.blocking;

import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * The block signals one JVM holds, shared by both broadcasters. A signal keeps the moment this JVM received it, so a
 * response is cut only by a BLOCK it did not pass: one received after the response started (the access filter reads
 * the response start before the decision in force). A signal stays after a cut, so every response of the user in
 * flight is cut; the release paths remove it, and an hour after its receipt it is dropped. A BLOCK in force is also
 * read through the probe, at most once per interval for a user and not before an interval of the response has passed,
 * so a signal this JVM did not receive still cuts. The time of a user's last probe is kept only while it can hold back
 * the user's next probe (QF-42).
 */
@Slf4j
final class BlockSignals {

    static final Duration DEFAULT_PROBE_INTERVAL = Duration.ofMillis(500);
    static final Duration RETENTION = Duration.ofHours(1);
    private static final int SWEEP_ABOVE = 10_000;

    private record Signal(String action, long receivedNanos) {
    }

    private final ConcurrentHashMap<String, Signal> signals = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> probedAt = new ConcurrentHashMap<>();
    private final BlockedStateProbe probe;
    private final long probeIntervalNanos;
    private final long retentionNanos = RETENTION.toNanos();
    private final LongSupplier clock;
    private volatile long probesForgottenAt;

    BlockSignals(BlockedStateProbe probe, Duration probeInterval, LongSupplier clock) {
        this.probe = probe;
        this.probeIntervalNanos = (probeInterval != null ? probeInterval : DEFAULT_PROBE_INTERVAL).toNanos();
        this.clock = clock != null ? clock : System::nanoTime;
        this.probesForgottenAt = now() - probeIntervalNanos;
    }

    long now() {
        return clock.getAsLong();
    }

    /** Records a received BLOCK; a signal already in force keeps its first receipt (an echo does not move it). */
    void put(String userId, String action) {
        long now = now();
        signals.compute(ZeroTrustUserKey.of(userId), (key, current) -> current != null && !expired(current, now)
                ? new Signal(action, current.receivedNanos())
                : new Signal(action, now));
        if (signals.size() > SWEEP_ABOVE) {
            sweep(now);
        }
    }

    void remove(String userId) {
        signals.remove(ZeroTrustUserKey.of(userId));
    }

    boolean contains(String userId) {
        return current(userId) != null;
    }

    String action(String userId) {
        Signal signal = current(userId);
        return signal != null ? signal.action() : null;
    }

    boolean cuts(String userId, long responseStartNanos) {
        Signal signal = current(userId);
        if (signal != null && signal.receivedNanos() - responseStartNanos >= 0) {
            return true;
        }
        return blockedInForce(userId, responseStartNanos);
    }

    private boolean blockedInForce(String userId, long responseStartNanos) {
        if (probe == null) {
            return false;
        }
        long now = now();
        String key = ZeroTrustUserKey.of(userId);
        Long last = probedAt.get(key);
        long since = last != null && last - responseStartNanos > 0 ? last : responseStartNanos;
        if (now - since < probeIntervalNanos) {
            return false;
        }
        probedAt.put(key, now);
        forgetOldProbes(now);
        boolean blocked;
        try {
            blocked = probe.isBlocked(userId);
        } catch (RuntimeException e) {
            log.error("[BlockSignals] Failed to read the decision in force: userId={}", userId, e);
            return false;
        }
        if (blocked) {
            put(userId, "BLOCK");
        }
        return blocked;
    }

    private Signal current(String userId) {
        String key = ZeroTrustUserKey.of(userId);
        Signal signal = signals.get(key);
        if (signal != null && expired(signal, now())) {
            signals.remove(key, signal);
            return null;
        }
        return signal;
    }

    private boolean expired(Signal signal, long now) {
        return now - signal.receivedNanos() >= retentionNanos;
    }

    int probedUsers() {
        return probedAt.size();
    }

    /**
     * QF-42: forgets, once many users were probed, the probe times older than the interval. Such a time no longer holds
     * back a probe (the next one waits for the interval from the later of it and the response start), so forgetting it
     * changes no answer. At most once per interval, so many users probed at once cost one pass.
     */
    private void forgetOldProbes(long now) {
        if (probedAt.size() <= SWEEP_ABOVE || now - probesForgottenAt < probeIntervalNanos) {
            return;
        }
        probesForgottenAt = now;
        probedAt.entrySet().removeIf(entry -> now - entry.getValue() >= probeIntervalNanos);
    }

    private void sweep(long now) {
        signals.entrySet().removeIf(entry -> expired(entry.getValue(), now));
        probedAt.entrySet().removeIf(entry -> now - entry.getValue() >= probeIntervalNanos);
    }
}
