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

import java.time.Duration;
import java.util.function.LongSupplier;

/**
 * In-memory implementation of BlockingSignalBroadcaster for standalone mode (one JVM). The probe reads the decision in
 * force from the decision store, so a BLOCK written without its signal still cuts.
 */
public class InMemoryBlockingSignalBroadcaster implements BlockingSignalBroadcaster {

    private final BlockSignals signals;

    public InMemoryBlockingSignalBroadcaster() {
        this(null, BlockSignals.DEFAULT_PROBE_INTERVAL);
    }

    public InMemoryBlockingSignalBroadcaster(BlockedStateProbe probe) {
        this(probe, BlockSignals.DEFAULT_PROBE_INTERVAL);
    }

    public InMemoryBlockingSignalBroadcaster(BlockedStateProbe probe, Duration probeInterval) {
        this(probe, probeInterval, System::nanoTime);
    }

    InMemoryBlockingSignalBroadcaster(BlockedStateProbe probe, Duration probeInterval, LongSupplier clock) {
        this.signals = new BlockSignals(probe, probeInterval, clock);
    }

    @Override
    public void registerBlock(String userId, String action) {
        if (userId != null && !userId.isBlank()) {
            signals.put(userId, (action != null && !action.isBlank()) ? action : "BLOCK");
        }
    }

    @Override
    public void registerUnblock(String userId) {
        if (userId != null && !userId.isBlank()) {
            signals.remove(userId);
        }
    }

    @Override
    public boolean isBlocked(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        return signals.contains(userId);
    }

    @Override
    public String getBlockAction(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        return signals.action(userId);
    }

    @Override
    public boolean shouldCut(String userId, long responseStartNanos) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        return signals.cuts(userId, responseStartNanos);
    }
}
