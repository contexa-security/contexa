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

/**
 * What became of the vector document stores that failed (BR-C4, QF-8), counted in documents since the service started.
 * A document that leaves the queue on purpose (deleted by id, or its user purged) is counted in none of retried,
 * dropped and pending, and a store that fails again while the same document already waits replaces the waiting copy and counts as
 * a failed store of its own, so {@code failed + deferred = retried + dropped + pending + removed on purpose + replaced}.
 *
 * @param failed   documents whose store failed and that were taken in for a retry
 * @param pending  documents that wait for a retry now
 * @param retried  documents that were stored by a retry
 * @param dropped  documents given up (tries or age used up) or pushed out of a full queue; each is also logged as an
 *                 error
 * @param deferred documents taken in for the retry without a store attempt, because the learning executor had no room
 *                 for their store (QF-25 b)
 */
public record StoreFailureStats(long failed, long pending, long retried, long dropped, long deferred) {

    /** The stats of a service that keeps no retry queue. */
    public static final StoreFailureStats NONE = new StoreFailureStats(0, 0, 0, 0, 0);

    /** The stats without a deferred store (the form before QF-25 b). */
    public StoreFailureStats(long failed, long pending, long retried, long dropped) {
        this(failed, pending, retried, dropped, 0);
    }
}
