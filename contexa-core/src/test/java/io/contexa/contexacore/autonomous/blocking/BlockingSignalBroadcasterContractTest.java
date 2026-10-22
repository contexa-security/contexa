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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * What a block signal decides for a response in flight, the same for the in-memory and the Redis broadcaster
 * (docs/showcase/응답차단-수정계획.md RT-1): a BLOCK received after the response started cuts it, one received before
 * does not, the signal stays after a cut so that every response of the user in flight is cut, and a BLOCK in force is
 * read once per interval so that a missed signal still cuts.
 */
abstract class BlockingSignalBroadcasterContractTest {

    private static final long MS = 1_000_000L;
    private static final Duration INTERVAL = Duration.ofMillis(500);

    protected final AtomicLong now = new AtomicLong(1_000 * MS);
    protected final Set<String> blockedInForce = ConcurrentHashMap.newKeySet();
    protected final AtomicInteger probeReads = new AtomicInteger();

    /** A broadcaster on the given clock; the probe reads {@link #blockedInForce}. */
    protected abstract BlockingSignalBroadcaster create(BlockedStateProbe probe, Duration probeInterval,
                                                        LongSupplier clock);

    private BlockingSignalBroadcaster broadcaster() {
        return create(userId -> {
            probeReads.incrementAndGet();
            return blockedInForce.contains(userId);
        }, INTERVAL, now::get);
    }

    protected static String user() {
        return "cut-" + UUID.randomUUID();
    }

    private long advance(long millis) {
        return now.addAndGet(millis * MS);
    }

    @Test
    @DisplayName("a BLOCK received after the response started cuts it")
    void aBlockReceivedAfterTheResponseStartedCutsIt() {
        BlockingSignalBroadcaster signals = broadcaster();
        String user = user();
        long started = now.get();
        advance(10);

        signals.registerBlock(user);

        assertThat(signals.shouldCut(user, started)).isTrue();
        assertThat(signals.isBlocked(user)).isTrue();
        assertThat(signals.getBlockAction(user)).isEqualTo("BLOCK");
    }

    @Test
    @DisplayName("a BLOCK received before the response started is a decision the response passed: it does not cut")
    void aBlockReceivedBeforeTheResponseStartedDoesNotCutIt() {
        BlockingSignalBroadcaster signals = broadcaster();
        String user = user();
        signals.registerBlock(user);
        advance(10);
        long started = now.get();

        assertThat(signals.shouldCut(user, started)).isFalse();
        assertThat(signals.isBlocked(user)).as("the signal itself is still registered").isTrue();
    }

    @Test
    @DisplayName("the signal stays after a cut, so every response of the user that started before it is cut")
    void theSignalStaysSoEveryResponseInFlightIsCut() {
        BlockingSignalBroadcaster signals = broadcaster();
        String user = user();
        long first = now.get();
        long second = advance(200);
        advance(10);

        signals.registerBlock(user);

        assertThat(signals.shouldCut(user, first)).isTrue();
        assertThat(signals.shouldCut(user, first)).as("asked again after the first cut").isTrue();
        assertThat(signals.shouldCut(user, second)).as("another response in flight").isTrue();
    }

    @Test
    @DisplayName("a released user is not cut, and a BLOCK again cuts")
    void aReleasedUserIsNotCutAndABlockAgainCuts() {
        BlockingSignalBroadcaster signals = broadcaster();
        String user = user();
        long started = now.get();
        advance(10);
        signals.registerBlock(user);
        settle(signals, user, true);

        signals.registerUnblock(user);
        settle(signals, user, false);
        assertThat(signals.shouldCut(user, started)).isFalse();

        advance(10);
        signals.registerBlock(user);
        await().atMost(Duration.ofSeconds(2)).until(() -> signals.shouldCut(user, started));
    }

    @Test
    @DisplayName("another user's BLOCK does not cut the response")
    void anotherUsersBlockDoesNotCut() {
        BlockingSignalBroadcaster signals = broadcaster();
        String user = user();
        long started = now.get();
        advance(10);

        signals.registerBlock(user());

        assertThat(signals.shouldCut(user, started)).isFalse();
    }

    @Test
    @DisplayName("a BLOCK in force cuts without its signal once the probe interval has passed")
    void aBlockInForceCutsWithoutTheSignal() {
        BlockingSignalBroadcaster signals = broadcaster();
        String user = user();
        long started = now.get();
        blockedInForce.add(user);

        advance(499);
        assertThat(signals.shouldCut(user, started)).as("before the interval").isFalse();
        advance(1);
        assertThat(signals.shouldCut(user, started)).as("at the interval").isTrue();
        assertThat(signals.isBlocked(user)).as("the BLOCK read in force becomes the signal").isTrue();
        assertThat(signals.shouldCut(user, started)).isTrue();
    }

    @Test
    @DisplayName("the decision in force is read at most once per interval for a user")
    void theDecisionInForceIsReadAtMostOncePerInterval() {
        BlockingSignalBroadcaster signals = broadcaster();
        String user = user();
        long started = now.get();

        advance(500);
        signals.shouldCut(user, started);
        signals.shouldCut(user, started);
        advance(100);
        signals.shouldCut(user, started);
        assertThat(probeReads).hasValue(1);

        advance(400);
        signals.shouldCut(user, started);
        assertThat(probeReads).hasValue(2);
    }

    @Test
    @DisplayName("a response shorter than the interval never reads the decision in force")
    void aShortResponseNeverReadsTheDecisionInForce() {
        BlockingSignalBroadcaster signals = broadcaster();
        String user = user();
        long started = now.get();

        for (int i = 0; i < 10; i++) {
            advance(49);
            assertThat(signals.shouldCut(user, started)).isFalse();
        }

        assertThat(probeReads).hasValue(0);
    }

    @Test
    @DisplayName("a probe that fails does not cut, and the next interval reads again")
    void aFailingProbeDoesNotCut() {
        AtomicInteger calls = new AtomicInteger();
        BlockingSignalBroadcaster signals = create(userId -> {
            if (calls.incrementAndGet() == 1) {
                throw new IllegalStateException("store unavailable");
            }
            return true;
        }, INTERVAL, now::get);
        String user = user();
        long started = now.get();

        advance(500);
        assertThat(signals.shouldCut(user, started)).isFalse();
        advance(500);
        assertThat(signals.shouldCut(user, started)).isTrue();
    }

    @Test
    @DisplayName("a signal is dropped an hour after it was received")
    void aSignalIsDroppedAfterItsRetention() {
        BlockingSignalBroadcaster signals = broadcaster();
        String user = user();
        signals.registerBlock(user);
        settle(signals, user, true);

        advance(Duration.ofHours(1).toMillis() - 1);
        assertThat(signals.isBlocked(user)).isTrue();
        advance(2);
        assertThat(signals.isBlocked(user)).isFalse();
    }

    @Test
    @DisplayName("a request without a user is never cut and never reads the decision in force")
    void aRequestWithoutAUserIsNeverCut() {
        BlockingSignalBroadcaster signals = broadcaster();
        long started = now.get();
        advance(1_000);

        assertThat(signals.shouldCut(null, started)).isFalse();
        assertThat(signals.shouldCut(" ", started)).isFalse();
        assertThat(probeReads).hasValue(0);
    }

    /** Waits until the broadcaster's state settled on {@code blocked}; Redis overrides it to let its own echo arrive. */
    protected void settle(BlockingSignalBroadcaster signals, String user, boolean blocked) {
        await().atMost(Duration.ofSeconds(2)).until(() -> signals.isBlocked(user) == blocked);
    }
}
