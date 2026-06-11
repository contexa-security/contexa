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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractBlockMfaStateStoreContractTest {

    protected ZeroTrustActionRepository actionRepository;
    protected BlockMfaStateStore store;

    protected abstract BlockMfaStateStore createStore(ZeroTrustActionRepository actionRepository);

    protected abstract BlockMfaStateStore createStoreWithVerifiedTtl(
            ZeroTrustActionRepository actionRepository, Duration verifiedTtl);

    @BeforeEach
    void setUpStore() {
        actionRepository = new InMemoryZeroTrustActionRepository();
        store = createStore(actionRepository);
    }

    @Test
    @DisplayName("isVerified returns false for fresh user")
    void verified_initiallyFalse() {
        assertThat(store.isVerified("fresh-user")).isFalse();
    }

    @Test
    @DisplayName("isVerified returns true right after setVerified")
    void verified_trueAfterSet() {
        store.setVerified("user1");

        assertThat(store.isVerified("user1")).isTrue();
    }

    @Test
    @DisplayName("Verified state expires after the configured TTL")
    void verified_expiresAfterTtl() {
        BlockMfaStateStore ttlStore = createStoreWithVerifiedTtl(actionRepository, Duration.ofMillis(200));
        ttlStore.setVerified("user-ttl");

        assertThat(ttlStore.isVerified("user-ttl")).isTrue();

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() ->
                        assertThat(ttlStore.isVerified("user-ttl"))
                                .as("verified state must expire after TTL")
                                .isFalse());
    }

    @Test
    @DisplayName("setPending writes to the shared ZeroTrustActionRepository")
    void setPending_sharedWithActionRepository() {
        store.setPending("user-pending");

        assertThat(actionRepository.isBlockMfaPending("user-pending"))
                .as("both modes must share pending state via ZeroTrustActionRepository")
                .isTrue();
    }

    @Test
    @DisplayName("clearPending clears state visible to the shared ZeroTrustActionRepository")
    void clearPending_sharedWithActionRepository() {
        store.setPending("user-pending");
        store.clearPending("user-pending");

        assertThat(actionRepository.isBlockMfaPending("user-pending")).isFalse();
    }

    @Test
    @DisplayName("getFailCount reads from the shared ZeroTrustActionRepository")
    void getFailCount_readsFromActionRepository() {
        actionRepository.incrementBlockMfaFailCount("user-fail");
        actionRepository.incrementBlockMfaFailCount("user-fail");
        actionRepository.incrementBlockMfaFailCount("user-fail");

        assertThat(store.getFailCount("user-fail"))
                .as("both modes must read fail count from ZeroTrustActionRepository")
                .isEqualTo(3);
    }

    @Test
    @DisplayName("getFailCount returns zero for unknown user")
    void getFailCount_unknownUser_returnsZero() {
        assertThat(store.getFailCount("ghost-user")).isZero();
    }
}
