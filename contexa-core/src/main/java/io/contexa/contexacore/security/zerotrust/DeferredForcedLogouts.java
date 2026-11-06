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
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.store.StoreFailures;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/**
 * The forced logouts Redis did not take while it was away, by user, until it takes them. One user waits once,
 * with the reason asked last; a forced logout can be applied any number of times. They are kept in the memory of the
 * node that was asked: a restart in the outage loses them, which the record of the request and the report at the stop
 * tell. Past the bound the one asked first goes, and that is reported too.
 */
@Slf4j
final class DeferredForcedLogouts {

    static final int MAX_WAITING = 10_000;

    private final int maxWaiting;
    private final Map<String, String> waiting = new LinkedHashMap<>();
    private final AtomicBoolean applying = new AtomicBoolean();

    DeferredForcedLogouts() {
        this(MAX_WAITING);
    }

    DeferredForcedLogouts(int maxWaiting) {
        this.maxWaiting = maxWaiting;
    }

    void defer(String userId, String reason) {
        String dropped = null;
        synchronized (this) {
            waiting.remove(userId);
            waiting.put(userId, reason);
            if (waiting.size() > maxWaiting) {
                dropped = waiting.keySet().iterator().next();
                waiting.remove(dropped);
            }
        }
        if (dropped != null) {
            log.error("[ZeroTrust] {} forced logouts are waiting for Redis, the most that are kept: the one of {} will not be "
                    + "applied.", maxWaiting, dropped);
        }
    }

    synchronized int size() {
        return waiting.size();
    }

    /**
     * Applies what waits, in the order it was asked. An outage ends the pass and what it did not reach stays; another
     * failure is reported and that logout is not tried again. One pass runs at a time.
     */
    void applyAll(BiConsumer<String, String> forcedLogout) {
        if (!applying.compareAndSet(false, true)) {
            return;
        }
        try {
            for (Map.Entry<String, String> next : snapshot()) {
                String userId = next.getKey();
                String reason = next.getValue();
                try {
                    forcedLogout.accept(userId, reason);
                } catch (RuntimeException failure) {
                    if (StoreFailures.isStoreFailure(failure)) {
                        return;
                    }
                    log.error("[ZeroTrust] A forced logout that waited for Redis could not be applied: userId={}", userId,
                            failure);
                }
                forget(userId, reason);
            }
        } finally {
            applying.set(false);
        }
    }

    private synchronized List<Map.Entry<String, String>> snapshot() {
        List<Map.Entry<String, String>> copy = new ArrayList<>(waiting.size());
        waiting.forEach((userId, reason) -> copy.add(Map.entry(userId, reason)));
        return copy;
    }

    /** A logout asked again meanwhile waits for the next pass. */
    private synchronized void forget(String userId, String reason) {
        waiting.remove(userId, reason);
    }
}
