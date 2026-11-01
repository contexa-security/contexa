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

    /** The decision repository of the same mode, which the store shares its state with. */
    protected ZeroTrustActionRepository createActionRepository() {
        return new InMemoryZeroTrustActionRepository();
    }

    @BeforeEach
    void setUpStore() {
        actionRepository = createActionRepository();
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
    @DisplayName("verified timestamps are exposed when the store can provide freshness metadata")
    void verified_exposesFreshnessMetadataWhenAvailable() {
        store.setVerified("user1");

        assertThat(store.isVerified("user1")).isTrue();
        if (store.getVerifiedAt("user1") != null) {
            assertThat(store.getVerifiedAt("user1")).isBeforeOrEqualTo(store.getVerifiedExpiresAt("user1"));
        }
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

    @Test
    @DisplayName("clearing a user removes its BLOCK MFA verification")
    void clearUser_removesVerification() {
        store.setVerified("gina");
        store.setVerified("hank");

        store.clearUser("gina");

        assertThat(store.isVerified("gina")).isFalse();
        assertThat(store.isVerified("hank")).isTrue();
    }

    // Z-16 (1-d): the verification goes with the user's other BLOCK MFA state, as the Redis keys do.

    @Test
    @DisplayName("a logout of a user nothing restricts clears its BLOCK MFA verification")
    void logoutOfAnUnrestrictedUser_clearsVerification() {
        store.setVerified("ivy");

        actionRepository.removeLogoutData("ivy");

        assertThat(store.isVerified("ivy")).isFalse();
    }

    @Test
    @DisplayName("a logout of a blocked user keeps its BLOCK MFA verification")
    void logoutOfABlockedUser_keepsVerification() {
        actionRepository.setBlockedFlag("jack");
        store.setVerified("jack");

        actionRepository.removeLogoutData("jack");

        assertThat(store.isVerified("jack")).isTrue();
        actionRepository.removeAllUserData("jack");
    }

    @Test
    @DisplayName("removing all of a user's data clears its BLOCK MFA verification")
    void removeAllUserData_clearsVerification() {
        store.setVerified("kate");
        store.setVerified("liam");

        actionRepository.removeAllUserData("kate");

        assertThat(store.isVerified("kate")).isFalse();
        assertThat(store.isVerified("liam")).isTrue();
    }

    @Test
    @DisplayName("removing the data of a user's agents clears their BLOCK MFA verifications only")
    void removeAllAgentData_clearsTheAgentsVerifications() {
        store.setVerified("mona");
        store.setVerified("mona::agent::reports");

        actionRepository.removeAllAgentData("mona");

        assertThat(store.isVerified("mona::agent::reports")).isFalse();
        assertThat(store.isVerified("mona")).isTrue();
    }
}
