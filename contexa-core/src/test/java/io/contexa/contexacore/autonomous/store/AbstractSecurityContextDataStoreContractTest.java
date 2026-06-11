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

import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractSecurityContextDataStoreContractTest {

    protected SecurityContextDataStore store;

    protected abstract SecurityContextDataStore createStore();

    protected abstract SecurityContextDataStore createStoreWithEventProcessedTtl(Duration ttl);

    @BeforeEach
    void setUpStore() {
        store = createStore();
    }

    @Test
    @DisplayName("claimEventProcessing returns ACQUIRED for a fresh event")
    void claim_freshEvent_acquired() {
        assertThat(store.claimEventProcessing("event-fresh"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);
    }

    @Test
    @DisplayName("claimEventProcessing returns IN_FLIGHT when already claimed but not yet marked processed")
    void claim_inFlight_afterAcquire() {
        store.claimEventProcessing("event-inflight");

        assertThat(store.claimEventProcessing("event-inflight"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.IN_FLIGHT);
    }

    @Test
    @DisplayName("claimEventProcessing returns PROCESSED after markEventProcessed")
    void claim_processed_afterMark() {
        store.claimEventProcessing("event-done");
        store.markEventProcessed("event-done");

        assertThat(store.claimEventProcessing("event-done"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.PROCESSED);
    }

    @Test
    @DisplayName("Processed event re-opens for claim after event-processed TTL expires")
    void markEventProcessed_expiresAfterTtl() {
        SecurityContextDataStore ttlStore = createStoreWithEventProcessedTtl(Duration.ofMillis(300));
        ttlStore.claimEventProcessing("event-ttl");
        ttlStore.markEventProcessed("event-ttl");

        assertThat(ttlStore.claimEventProcessing("event-ttl"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.PROCESSED);

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() -> assertThat(ttlStore.claimEventProcessing("event-ttl"))
                        .as("processed event must become claimable again after TTL")
                        .isEqualTo(SecurityContextDataStore.EventProcessingClaim.ACQUIRED));
    }

    @Test
    @DisplayName("releaseEventProcessing frees an in-flight claim")
    void release_freesInFlight() {
        store.claimEventProcessing("event-rel");
        store.releaseEventProcessing("event-rel");

        assertThat(store.claimEventProcessing("event-rel"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);
    }
}
