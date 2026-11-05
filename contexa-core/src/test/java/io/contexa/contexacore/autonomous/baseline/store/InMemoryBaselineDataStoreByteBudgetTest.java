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
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.store.ExpiringKeyBudget;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The personal baselines of the in-memory store have a limit in bytes, each baseline counted at its text.
 * Below it nothing changes; past it the baselines saved the longest ago go first. The organization baselines, which
 * every new member is compared with, are not among them.
 */
class InMemoryBaselineDataStoreByteBudgetTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30), clock);

    private static BaselineVector baseline(String user) {
        return BaselineVector.builder().userId(user).frequentPaths(new String[]{"/orders", "/reports"})
                .elementFrequencies(Map.of("path:/orders", 3L)).build();
    }

    private long bytesOf(String user) {
        return 2L * baseline(user).toString().length();
    }

    private void save(String user) {
        store.saveUserBaseline(user, baseline(user));
        clock.advance(Duration.ofMillis(1));
    }

    @Test
    void belowTheLimitEveryBaselineStays() {
        store.setUserBaselineBudgetBytes(10 * bytesOf("user-0"));
        for (int user = 0; user < 10; user++) {
            save("user-" + user);
        }

        assertThat(store.countUserBaselines()).isEqualTo(10);
        assertThat(store.userBaselineBytes()).isEqualTo(10 * bytesOf("user-0"));
    }

    @Test
    void pastTheLimitTheBaselineSavedTheLongestAgoGoesFirst() {
        store.setUserBaselineBudgetBytes(3 * bytesOf("user-a"));
        save("user-a");
        save("user-b");
        save("user-c");
        save("user-a");

        save("user-d");

        assertThat(store.getUserBaseline("user-b")).as("saved the longest ago").isNull();
        assertThat(store.getUserBaseline("user-a")).as("saved again").isNotNull();
        assertThat(store.getUserBaseline("user-c")).isNotNull();
        assertThat(store.getUserBaseline("user-d")).isNotNull();
        assertThat(store.userBaselineBytes()).isEqualTo(3 * bytesOf("user-a"));
    }

    @Test
    void aBaselineSavedAgainIsCountedAtWhatItIsNow() {
        save("user-a");
        BaselineVector grown = baseline("user-a");
        grown.setFrequentPaths(new String[]{"/orders", "/reports", "/invoices", "/customers"});

        store.saveUserBaseline("user-a", grown);

        assertThat(store.userBaselineBytes()).isEqualTo(2L * grown.toString().length());
    }

    @Test
    void everyWayOutLeavesTheCount() {
        save("user-a");
        save("tenant::user-b");
        save("owner" + LearningSubject.AGENT_KEY + "bot-1");
        save("user-c");
        save("user-d");

        store.deleteUserBaseline("user-a");
        store.deleteAgentBaselines("bot-1");
        store.deleteUserBaselineKey("user-c");
        assertThat(store.userBaselineBytes()).isEqualTo(bytesOf("tenant::user-b") + bytesOf("user-d"));

        clock.advance(Duration.ofDays(31));
        store.removeExpiredEntries();
        assertThat(store.userBaselineBytes()).isZero();
    }

    @Test
    void anOrganizationBaselineIsNotCountedAndDoesNotGoForTheLimit() {
        store.setUserBaselineBudgetBytes(bytesOf("user-a"));
        store.saveOrganizationBaseline("org", baseline("org"));

        save("user-a");
        save("user-b");

        assertThat(store.getOrganizationBaseline("org")).isNotNull();
        assertThat(store.userBaselineBytes()).isEqualTo(bytesOf("user-b"));
    }

    @Test
    void theDefaultLimitFollowsTheHeap() {
        assertThat(new InMemoryBaselineDataStore().userBaselineBudgetBytes())
                .isEqualTo(ExpiringKeyBudget.defaultLimitBytes(Runtime.getRuntime().maxMemory()));
    }
}
