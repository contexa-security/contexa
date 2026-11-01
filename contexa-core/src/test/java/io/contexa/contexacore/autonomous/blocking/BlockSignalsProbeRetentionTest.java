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

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: the time of a user's last probe is kept only while it can still hold back the user's next probe (one probe
 * interval); the users of every response that waited past the interval no longer pile up.
 */
class BlockSignalsProbeRetentionTest {

    private static final Duration INTERVAL = Duration.ofMillis(500);

    private final AtomicLong now = new AtomicLong();
    private final AtomicInteger probes = new AtomicInteger();
    private final BlockSignals signals = new BlockSignals(userId -> {
        probes.incrementAndGet();
        return false;
    }, INTERVAL, now::get);

    @Test
    void theProbeTimesOfUsersNoLongerProbedAreForgotten() {
        for (int user = 0; user < 20_000; user++) {
            now.addAndGet(Duration.ofMillis(1).toNanos());
            assertThat(signals.cuts("user-" + user, now.get() - Duration.ofSeconds(1).toNanos())).isFalse();
        }

        assertThat(probes).hasValue(20_000);
        assertThat(signals.probedUsers()).isLessThanOrEqualTo(10_000 + 500);
    }

    @Test
    void aRecentProbeStillHoldsBackTheUsersNextOne() {
        long responseStart = now.get();
        now.addAndGet(INTERVAL.toNanos());
        for (int user = 0; user < 20_000; user++) {
            signals.cuts("user-" + user, responseStart);
        }
        now.addAndGet(Duration.ofMillis(600).toNanos());
        signals.cuts("alice", responseStart);
        assertThat(probes).hasValue(20_001);
        assertThat(signals.probedUsers()).isEqualTo(1);

        now.addAndGet(INTERVAL.toNanos() - 1);
        signals.cuts("alice", responseStart);
        assertThat(probes).as("within the interval of alice's last probe").hasValue(20_001);

        now.addAndGet(1);
        signals.cuts("alice", responseStart);
        assertThat(probes).hasValue(20_002);
    }
}
