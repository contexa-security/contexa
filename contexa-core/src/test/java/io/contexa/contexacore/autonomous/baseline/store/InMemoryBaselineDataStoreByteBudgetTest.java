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
 * The personal and the organization baselines of the in-memory store each have a limit in bytes, a baseline counted at
 * its text. Below it nothing changes; past it the baselines saved the longest ago go first. Neither kind goes for the
 * other: personal baselines do not push out an organization's, which every new member is compared with.
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

    private void saveOrg(String organization) {
        store.saveOrganizationBaseline(organization, baseline(organization));
        clock.advance(Duration.ofMillis(1));
    }

    private int organizations() {
        int organizations = 0;
        for (BaselineVector ignored : store.listOrganizationBaselines()) {
            organizations++;
        }
        return organizations;
    }

    @Test
    void belowTheLimitEveryOrganizationBaselineStays() {
        store.setOrgBaselineBudgetBytes(10 * bytesOf("org-0"));
        for (int organization = 0; organization < 10; organization++) {
            saveOrg("org-" + organization);
        }

        assertThat(organizations()).isEqualTo(10);
        assertThat(store.orgBaselineBytes()).isEqualTo(10 * bytesOf("org-0"));
    }

    @Test
    void pastTheLimitTheOrganizationBaselineSavedTheLongestAgoGoesFirst() {
        store.setOrgBaselineBudgetBytes(3 * bytesOf("org-a"));
        saveOrg("org-a");
        saveOrg("org-b");
        saveOrg("org-c");
        saveOrg("org-a");

        saveOrg("org-d");

        assertThat(store.getOrganizationBaseline("org-b")).as("saved the longest ago").isNull();
        assertThat(store.getOrganizationBaseline("org-a")).as("saved again").isNotNull();
        assertThat(store.getOrganizationBaseline("org-c")).isNotNull();
        assertThat(store.getOrganizationBaseline("org-d")).isNotNull();
        assertThat(store.orgBaselineBytes()).isEqualTo(3 * bytesOf("org-a"));
    }

    @Test
    void anOrganizationBaselineSavedAgainIsCountedAtWhatItIsNow() {
        saveOrg("org-a");
        BaselineVector grown = baseline("org-a");
        grown.setFrequentPaths(new String[]{"/orders", "/reports", "/invoices", "/customers"});

        store.saveOrganizationBaseline("org-a", grown);

        assertThat(store.orgBaselineBytes()).isEqualTo(2L * grown.toString().length());
    }

    @Test
    void anExpiredOrganizationBaselineLeavesTheCount() {
        saveOrg("org-a");

        clock.advance(Duration.ofDays(31));
        store.removeExpiredEntries();

        assertThat(store.orgBaselineBytes()).isZero();
    }

    @Test
    void anOrganizationBaselinePastItsLimitPushesOutNoPersonalOne() {
        store.setOrgBaselineBudgetBytes(bytesOf("org-a"));
        save("user-a");

        saveOrg("org-a");
        saveOrg("org-b");

        assertThat(store.getUserBaseline("user-a")).isNotNull();
        assertThat(store.getOrganizationBaseline("org-a")).isNull();
        assertThat(store.getOrganizationBaseline("org-b")).isNotNull();
    }

    @Test
    void theDefaultLimitFollowsTheHeap() {
        assertThat(new InMemoryBaselineDataStore().userBaselineBudgetBytes())
                .isEqualTo(ExpiringKeyBudget.defaultLimitBytes(Runtime.getRuntime().maxMemory()));
        assertThat(new InMemoryBaselineDataStore().orgBaselineBudgetBytes())
                .isEqualTo(ExpiringKeyBudget.defaultLimitBytes(Runtime.getRuntime().maxMemory()));
    }
}
