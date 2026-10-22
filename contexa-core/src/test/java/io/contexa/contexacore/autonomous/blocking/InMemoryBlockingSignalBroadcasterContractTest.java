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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.function.LongSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** The standalone broadcaster under the shared contract, and with the in-memory decision store as its probe. */
class InMemoryBlockingSignalBroadcasterContractTest extends BlockingSignalBroadcasterContractTest {

    @Override
    protected BlockingSignalBroadcaster create(BlockedStateProbe probe, Duration probeInterval, LongSupplier clock) {
        return new InMemoryBlockingSignalBroadcaster(probe, probeInterval, clock);
    }

    @Test
    @DisplayName("with the in-memory decision store as its probe, a BLOCK written without a signal cuts within 1 s")
    void aBlockWrittenToTheStoreWithoutASignalCuts() {
        InMemoryZeroTrustActionRepository store = new InMemoryZeroTrustActionRepository();
        BlockingSignalBroadcaster signals = new InMemoryBlockingSignalBroadcaster(
                userId -> store.getCurrentAction(userId, null) == ZeroTrustAction.BLOCK, Duration.ofMillis(500));
        String user = user();
        long started = System.nanoTime();

        store.setBlockedFlag(user);

        assertThat(signals.shouldCut(user, started)).as("not yet read").isFalse();
        await().atMost(Duration.ofSeconds(1)).until(() -> signals.shouldCut(user, started));
    }
}
