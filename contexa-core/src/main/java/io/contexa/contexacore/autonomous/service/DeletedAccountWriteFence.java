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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tells the late writes of a deleted account apart from those of a later account of the same name (Q-15). The purge of
 * a deleted account runs once, after the deletion commits, while the analysis of a request the account made before may
 * still run (for the event budget, and again for each deferred retry) and its learning may still wait on an executor.
 * What they write after the purge would outlive the deletion and pass to a later account of the same name. The purge
 * therefore marks the deletion with its time before it removes anything; a write for a request the engine took in at
 * or before that time is discarded, while a request taken in after it belongs to a later account and is written.
 * <p>
 * The mark lasts the retention on the server clock, in the {@link SecurityContextDataStore} (in memory, or shared by
 * every instance in Redis). The time a request is compared at is the one the engine took it in ({@value #TAKEN_IN_AT},
 * set by the collectors and by the synchronous analysis), not the request's own observed time, which a host may state
 * on another clock; a write for an event without it is compared at the time it is asked for. Discarded writes are
 * counted by kind. Without a store nothing is marked and nothing is discarded.
 */
public class DeletedAccountWriteFence {

    /** The event metadata key holding when the engine took the event in, in epoch milliseconds of the server clock. */
    public static final String TAKEN_IN_AT = "ingestAt";

    /** The result of an analysis: the action in force, the block, the held requests and what is learned from it. */
    public static final String ENFORCEMENT = "enforcement";
    public static final String BASELINE = "baseline";
    public static final String SESSION_CONTEXT = "session-context";
    public static final String DECISION_DOCUMENT = "decision-document";
    /** A decision document that was stored while the purge ran, removed after it was stored. */
    public static final String DECISION_DOCUMENT_REMOVED = "decision-document-removed";

    private final SecurityContextDataStore store;
    private final Duration retention;
    private final Clock clock;
    private final Map<String, AtomicLong> discarded = new ConcurrentHashMap<>();

    public DeletedAccountWriteFence(SecurityContextDataStore store, Duration retention) {
        this(store, retention, Clock.systemUTC());
    }

    public DeletedAccountWriteFence(SecurityContextDataStore store, Duration retention, Clock clock) {
        this.store = store;
        this.retention = retention;
        this.clock = clock;
    }

    /**
     * How long a deletion is remembered: every attempt the event budget allows the analysis of one request (the first
     * and each deferred retry), and a margin for the queues and the learning executors.
     */
    public static Duration retention(long eventTimeoutMs, int maxDeferredRetries, long marginMs) {
        long attempts = Math.max(0, maxDeferredRetries) + 1L;
        return Duration.ofMillis(Math.max(1000L, eventTimeoutMs) * attempts + Math.max(0L, marginMs));
    }

    /** Marks the user's account deleted now; the purge calls it before it removes the user's state. */
    public void markDeleted(String userId) {
        if (store != null && userId != null && !userId.isBlank()) {
            store.recordAccountDeletion(userId, clock.instant(), retention);
        }
    }

    /** When the engine took the event in, else now: the time a write for the event is compared at. */
    public long takenInAt(SecurityEvent event) {
        Object takenIn = event != null && event.getMetadata() != null ? event.getMetadata().get(TAKEN_IN_AT) : null;
        return takenIn instanceof Number at ? at.longValue() : clock.millis();
    }

    /** Whether a request taken in at that time belongs to the user's account deleted since, while it is remembered. */
    public boolean fenced(String userId, long takenInAt) {
        if (store == null || userId == null || userId.isBlank()) {
            return false;
        }
        Instant deletedAt = store.accountDeletedAt(userId);
        return deletedAt != null && takenInAt <= deletedAt.toEpochMilli();
    }

    /** Whether the write is discarded as {@link #fenced}; a discarded write is counted under its kind. */
    public boolean discards(String write, String userId, long takenInAt) {
        if (!fenced(userId, takenInAt)) {
            return false;
        }
        discarded.computeIfAbsent(write, ignored -> new AtomicLong()).incrementAndGet();
        return true;
    }

    /** The writes discarded since the start, by kind. */
    public Map<String, Long> discardedWrites() {
        Map<String, Long> counts = new TreeMap<>();
        discarded.forEach((write, count) -> counts.put(write, count.get()));
        return Collections.unmodifiableMap(counts);
    }
}
