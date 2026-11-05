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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Consumer;

/**
 * The stores Contexa's requests read, and the record of what passed while they could not decide (Q-7). A store outage is
 * no reason to stop the application: its protected calls go on as the operating mode specifies, and nothing decided them.
 * Without Redis or the database nothing can write that down at the moment it happens, so the calls are counted here and
 * the count is reported at ERROR at once and once a minute, and written to the audit log when the database takes it.
 */
@Slf4j
public final class ContexaStores implements DisposableBean {

    /** The protected calls that went on without a decision between two moments. */
    public record UndecidedCalls(Instant from, Instant to, long calls) {
    }

    private static final Duration REPORT_INTERVAL = Duration.ofMinutes(1);

    private final StoreGate redis = new StoreGate("Redis", this::recordUndecided);
    private final StoreGate database = new StoreGate("Contexa's database", this::recordUndecided);
    private final Object ledger = new Object();
    private volatile Consumer<UndecidedCalls> recorder = calls -> {
    };
    private long undecided;
    private Instant undecidedFrom;
    private long reportedAtMillis;

    public StoreGate redis() {
        return redis;
    }

    public StoreGate database() {
        return database;
    }

    public boolean anyDown() {
        return redis.isDown() || database.isDown();
    }

    /** Where the record of the undecided calls is written, once it can be. */
    public void setRecorder(Consumer<UndecidedCalls> recorder) {
        this.recorder = recorder;
    }

    /** A protected call went on and nothing decided it. */
    public void passedWithoutDecision() {
        long now = System.currentTimeMillis();
        long calls;
        synchronized (ledger) {
            undecided++;
            if (undecidedFrom == null) {
                undecidedFrom = Instant.ofEpochMilli(now);
            }
            if (now - reportedAtMillis < REPORT_INTERVAL.toMillis()) {
                return;
            }
            reportedAtMillis = now;
            calls = undecided;
        }
        log.error("[Contexa] {} protected calls went on without a decision: a store Contexa decides with did not answer.", calls);
        recordUndecided();
    }

    /** Writes down what was counted; the count starts again with what the record holds. */
    private void recordUndecided() {
        if (database.isDown()) {
            return;
        }
        UndecidedCalls record;
        synchronized (ledger) {
            if (undecided == 0L) {
                return;
            }
            record = new UndecidedCalls(undecidedFrom, Instant.now(), undecided);
            undecided = 0L;
            undecidedFrom = null;
        }
        try {
            recorder.accept(record);
        } catch (RuntimeException failure) {
            log.error("[Contexa] {} protected calls between {} and {} went on without a decision, and the audit log did "
                    + "not take the record.", record.calls(), record.from(), record.to(), failure);
        }
    }

    @Override
    public void destroy() {
        redis.stop();
        database.stop();
    }
}
