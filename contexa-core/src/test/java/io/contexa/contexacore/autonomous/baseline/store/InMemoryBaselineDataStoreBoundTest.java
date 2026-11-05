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
package io.contexa.contexacore.autonomous.baseline.store;

import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Z-16 (F1): past its 100,000 baselines the in-memory store lets the baseline saved the longest ago go first, as Redis
 * {@code volatile-ttl} evicts the key whose TTL ends first; a baseline saved again is among the newest.
 */
class InMemoryBaselineDataStoreBoundTest {

    private static final int MAX_BASELINES = 100_000;

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30), clock);
    private final BaselineVector baseline = BaselineVector.builder().userId("bounded").avgTrustScore(0.5).build();

    @Test
    void pastTheBoundTheBaselineSavedTheLongestAgoGoesFirst() {
        // The bound on the number is what is held here; the limit in bytes follows the heap of the test.
        store.setUserBaselineBudgetBytes(Long.MAX_VALUE);
        for (int user = 0; user < MAX_BASELINES; user++) {
            store.saveUserBaseline("user-" + user, baseline);
            clock.advance(Duration.ofMillis(1));
        }
        store.saveUserBaseline("user-0", baseline);
        clock.advance(Duration.ofMillis(1));

        store.saveUserBaseline("newcomer", baseline);

        assertThat(store.countUserBaselines()).isEqualTo(MAX_BASELINES);
        assertThat(store.getUserBaseline("user-1")).as("saved the longest ago").isNull();
        assertThat(store.getUserBaseline("user-0")).as("saved again").isNotNull();
        assertThat(store.getUserBaseline("user-2")).isNotNull();
        assertThat(store.getUserBaseline("newcomer")).isNotNull();
    }
}
