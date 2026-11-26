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
package io.contexa.contexaiam.admin.web.auth.filter;

import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;

import java.time.Clock;
import java.time.Duration;

/**
 * When Contexa last checked and tracked each session, kept on Contexa's side and by the sessions' references, so that the
 * application's session carries nothing of Contexa's: the tracking reads its id only (R-8 of
 * docs/agent/운영모드-정상화-구현계획.md).
 * <p>
 * The marks only spare the database: a session is read for a forced end at most every {@link #EXPIRY_CHECK_INTERVAL}
 * and its activity written at most every {@link #TRACKING_INTERVAL}. Each node keeps its own. Where nodes share their
 * sessions, a node that has no mark of a session reads or writes it once more than it needs to: the read finds the same
 * row, and the write is the same idempotent upsert. Nothing that decides an outcome, such as whether a session that ends
 * has a row to end, is read from them.
 */
public class TrackedSessionMarks implements ExpiringStateStore {

    /** How often a session is read for a forced end. */
    public static final Duration EXPIRY_CHECK_INTERVAL = Duration.ofSeconds(10);
    /** How often a session's activity is written. */
    public static final Duration TRACKING_INTERVAL = Duration.ofSeconds(30);
    /** How many sessions the marks keep at most, for the memory of the node. */
    static final int SESSIONS_KEPT = 100_000;

    private final ExpiringKeySpace<Boolean> checked;
    private final ExpiringKeySpace<Boolean> tracked;

    public TrackedSessionMarks() {
        this(Clock.systemUTC());
    }

    public TrackedSessionMarks(Clock clock) {
        this.checked = ExpiringKeySpace.<Boolean>builder(clock).ttl(EXPIRY_CHECK_INTERVAL).bound(SESSIONS_KEPT).build();
        this.tracked = ExpiringKeySpace.<Boolean>builder(clock).ttl(TRACKING_INTERVAL).bound(SESSIONS_KEPT).build();
    }

    /** Whether the session is due a check for a forced end; it counts as checked from now when it is. */
    public boolean checkDue(String reference) {
        return checked.putIfAbsent(reference, Boolean.TRUE);
    }

    /** Whether the session's activity is due to be written; it counts as written from now when it is. */
    public boolean trackDue(String reference) {
        return tracked.putIfAbsent(reference, Boolean.TRUE);
    }

    /** Forgets the session: it ended, or its id was replaced. */
    public void forget(String reference) {
        checked.remove(reference);
        tracked.remove(reference);
    }

    @Override
    public void removeExpiredEntries() {
        checked.removeExpired();
        tracked.removeExpired();
    }
}
