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
package io.contexa.contexacore.hcad.store;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractBaselineDataStoreContractTest {

    protected BaselineDataStore store;

    protected abstract BaselineDataStore createStore();

    protected abstract BaselineDataStore createStoreWithTtl(Duration ttl);

    @BeforeEach
    void setUpStore() {
        store = createStore();
    }

    private BaselineVector userBaseline(String userId) {
        return BaselineVector.builder()
                .userId(userId)
                .updateCount(5L)
                .avgTrustScore(0.9)
                .build();
    }

    private BaselineVector orgBaseline(String orgId) {
        return BaselineVector.builder()
                .userId(orgId)
                .updateCount(12L)
                .avgTrustScore(0.85)
                .build();
    }

    @Test
    @DisplayName("getUserBaseline returns null when no baseline was saved")
    void user_unknown_returnsNull() {
        assertThat(store.getUserBaseline("unknown")).isNull();
    }

    @Test
    @DisplayName("saveUserBaseline is retrievable via getUserBaseline")
    void user_saveAndRetrieve() {
        store.saveUserBaseline("u1", userBaseline("u1"));

        BaselineVector loaded = store.getUserBaseline("u1");
        assertThat(loaded).isNotNull();
        assertThat(loaded.getUpdateCount()).isEqualTo(5L);
    }

    @Test
    @DisplayName("getOrganizationBaseline returns null when absent")
    void org_unknown_returnsNull() {
        assertThat(store.getOrganizationBaseline("unknown-org")).isNull();
    }

    @Test
    @DisplayName("saveOrganizationBaseline is retrievable via getOrganizationBaseline")
    void org_saveAndRetrieve() {
        store.saveOrganizationBaseline("org1", orgBaseline("org1"));

        BaselineVector loaded = store.getOrganizationBaseline("org1");
        assertThat(loaded).isNotNull();
        assertThat(loaded.getUpdateCount()).isEqualTo(12L);
    }

    @Test
    @DisplayName("countUserBaselines returns the number of saved user baselines")
    void count_returnsSavedUsers() {
        store.saveUserBaseline("u1", userBaseline("u1"));
        store.saveUserBaseline("u2", userBaseline("u2"));
        store.saveUserBaseline("u3", userBaseline("u3"));

        assertThat(store.countUserBaselines()).isEqualTo(3L);
    }

    @Test
    @DisplayName("User baseline is gone after the configured TTL expires")
    void user_expiresAfterTtl() {
        BaselineDataStore ttlStore = createStoreWithTtl(Duration.ofMillis(200));
        ttlStore.saveUserBaseline("u-ttl", userBaseline("u-ttl"));

        assertThat(ttlStore.getUserBaseline("u-ttl")).isNotNull();

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() -> assertThat(ttlStore.getUserBaseline("u-ttl"))
                        .as("user baseline must expire after TTL in both modes")
                        .isNull());
    }

    @Test
    @DisplayName("listOrganizationBaselines returns every saved organization baseline")
    void list_returnsAllSavedOrganizations() {
        store.saveOrganizationBaseline("org-a", orgBaseline("org-a"));
        store.saveOrganizationBaseline("org-b", orgBaseline("org-b"));
        store.saveOrganizationBaseline("org-c", orgBaseline("org-c"));

        java.util.List<BaselineVector> loaded = new java.util.ArrayList<>();
        store.listOrganizationBaselines().forEach(loaded::add);

        assertThat(loaded)
                .as("listOrganizationBaselines must return all saved org baselines without relying on KEYS scan")
                .hasSize(3);
    }

    @Test
    @DisplayName("countUserBaselines returns distinct user count even after repeated saves")
    void count_distinctCountAfterRepeatedSaves() {
        store.saveUserBaseline("u-rep", userBaseline("u-rep"));
        store.saveUserBaseline("u-rep", userBaseline("u-rep"));
        store.saveUserBaseline("u-rep", userBaseline("u-rep"));

        assertThat(store.countUserBaselines()).isEqualTo(1L);
    }

    @Test
    @DisplayName("User baseline preserves array values that contain commas and equals signs")
    void user_preservesSpecialCharactersInArrays() {
        String[] frequentPathsWithCommas = {
                "/api/v1,beta",
                "/api/reports?filter=a=b,c=d",
                "/normal/path"
        };
        BaselineVector baseline = BaselineVector.builder()
                .userId("u-special")
                .frequentPaths(frequentPathsWithCommas)
                .build();

        store.saveUserBaseline("u-special", baseline);

        BaselineVector loaded = store.getUserBaseline("u-special");
        assertThat(loaded).isNotNull();
        assertThat(loaded.getFrequentPaths())
                .as("array values with commas must round-trip intact under both memory and Redis")
                .containsExactly(frequentPathsWithCommas);
    }

    @Test
    @DisplayName("Organization baseline is gone after the configured TTL expires")
    void org_expiresAfterTtl() {
        BaselineDataStore ttlStore = createStoreWithTtl(Duration.ofMillis(200));
        ttlStore.saveOrganizationBaseline("org-ttl", orgBaseline("org-ttl"));

        assertThat(ttlStore.getOrganizationBaseline("org-ttl")).isNotNull();

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() -> assertThat(ttlStore.getOrganizationBaseline("org-ttl"))
                        .as("organization baseline must expire after TTL in both modes")
                        .isNull());
    }
}
