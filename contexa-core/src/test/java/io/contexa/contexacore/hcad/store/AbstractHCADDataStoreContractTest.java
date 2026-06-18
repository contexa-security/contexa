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

import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractHCADDataStoreContractTest {

    protected HCADDataStore store;

    protected abstract HCADDataStore createStore();

    protected abstract HCADDataStore createStoreWithMfaTtl(Duration mfaVerifiedTtl);

    @BeforeEach
    void setUpStore() {
        store = createStore();
    }

    @Test
    @DisplayName("Session metadata saved and retrieved identically")
    void sessionMetadata_saveAndRetrieve() {
        Map<String, Object> metadata = Map.of(
                "ip", "192.168.1.1",
                "userAgent", "Chrome/120"
        );

        store.saveSessionMetadata("session1", metadata);

        Map<Object, Object> result = store.getSessionMetadata("session1");
        assertThat(result).containsEntry("ip", "192.168.1.1");
        assertThat(result).containsEntry("userAgent", "Chrome/120");
    }

    @Test
    @DisplayName("Unknown session metadata returns empty map")
    void sessionMetadata_unknownSession_returnsEmpty() {
        Map<Object, Object> result = store.getSessionMetadata("unknown-session");

        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("Device registration is detectable")
    void device_registerAndCheck() {
        store.registerDevice("user1", "device-abc");

        assertThat(store.isDeviceRegistered("user1", "device-abc")).isTrue();
    }

    @Test
    @DisplayName("Unregistered device returns false")
    void device_unregistered_returnsFalse() {
        assertThat(store.isDeviceRegistered("user1", "device-xyz")).isFalse();
    }

    @Test
    @DisplayName("Device count never exceeds the maximum allowed")
    void device_maxLimitEnforced() {
        for (int i = 0; i < 15; i++) {
            store.registerDevice("user-cap", "device-" + i);
        }

        int registered = 0;
        for (int i = 0; i < 15; i++) {
            if (store.isDeviceRegistered("user-cap", "device-" + i)) {
                registered++;
            }
        }
        assertThat(registered).isLessThanOrEqualTo(10);
    }

    @Test
    @DisplayName("Oldest device is evicted first when the cap is exceeded")
    void device_capExceeded_evictsOldestFirst() {
        List<String> registrationOrder = new ArrayList<>();
        for (int i = 0; i < 11; i++) {
            String device = "device-" + i;
            registrationOrder.add(device);
            store.registerDevice("user-fifo", device);
        }

        String firstRegistered = registrationOrder.get(0);
        String lastRegistered = registrationOrder.get(10);

        assertThat(store.isDeviceRegistered("user-fifo", firstRegistered))
                .as("earliest registered device must be evicted first under FIFO")
                .isFalse();
        assertThat(store.isDeviceRegistered("user-fifo", lastRegistered))
                .as("most recent device must remain")
                .isTrue();
    }

    @Test
    @DisplayName("Request count inside window is accurate")
    void request_countInsideWindow() {
        long now = System.currentTimeMillis();
        store.recordRequest("user1", now - 60_000);
        store.recordRequest("user1", now - 30_000);
        store.recordRequest("user1", now);

        int count = store.getRecentRequestCount("user1", now - 120_000, now);

        assertThat(count).isEqualTo(3);
    }

    @Test
    @DisplayName("Multiple requests in the same millisecond are counted independently")
    void request_sameMillisecond_countedIndependently() {
        long now = System.currentTimeMillis();
        store.recordRequest("user-same-ms", now);
        store.recordRequest("user-same-ms", now);
        store.recordRequest("user-same-ms", now);

        int count = store.getRecentRequestCount("user-same-ms", now - 1, now);

        assertThat(count).isEqualTo(3);
    }

    @Test
    @DisplayName("Requests outside 5-minute window are excluded")
    void request_outsideWindow_excluded() {
        long now = System.currentTimeMillis();
        long sixMinutesAgo = now - 6 * 60 * 1000;

        store.recordRequest("user1", sixMinutesAgo);
        store.recordRequest("user1", now);

        int count = store.getRecentRequestCount("user1", sixMinutesAgo, now);
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("Request count returns zero for unknown user")
    void request_unknownUser_returnsZero() {
        long now = System.currentTimeMillis();
        int count = store.getRecentRequestCount("ghost-user", now - 300_000, now);

        assertThat(count).isZero();
    }

    @Test
    @DisplayName("User registration flag is observable")
    void user_registerAndCheck() {
        store.registerUser("user1");

        assertThat(store.isUserRegistered("user1")).isTrue();
    }

    @Test
    @DisplayName("Unregistered user reports false")
    void user_unknown_returnsFalse() {
        assertThat(store.isUserRegistered("ghost-user")).isFalse();
    }

    @Test
    @DisplayName("MFA verification starts as false for fresh user")
    void mfa_unverifiedByDefault() {
        assertThat(store.isMfaVerified("fresh-user")).isFalse();
    }

    @Test
    @DisplayName("MFA verification is true immediately after markMfaVerified")
    void mfa_trueImmediatelyAfterMark() {
        store.markMfaVerified("user-mfa-fresh");

        assertThat(store.isMfaVerified("user-mfa-fresh")).isTrue();
    }

    @Test
    @DisplayName("MFA verification expires after the configured TTL")
    void mfa_expiresAfterTtl() {
        HCADDataStore ttlStore = createStoreWithMfaTtl(Duration.ofMillis(200));
        ttlStore.markMfaVerified("user-mfa-expiring");

        assertThat(ttlStore.isMfaVerified("user-mfa-expiring"))
                .as("must be verified right after markMfaVerified")
                .isTrue();

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() ->
                        assertThat(ttlStore.isMfaVerified("user-mfa-expiring"))
                                .as("MFA verification must expire after TTL for both memory and Redis")
                                .isFalse());
    }

    @Test
    @DisplayName("HCAD analysis saved and retrieved identically")
    void hcadAnalysis_saveAndRetrieve() {
        Map<String, Object> analysis = new HashMap<>();
        analysis.put("anomalyScore", 0.85);
        analysis.put("category", "suspicious");

        store.saveHcadAnalysis("user1", analysis);

        Map<Object, Object> result = store.getHcadAnalysis("user1");
        assertThat(result).containsEntry("anomalyScore", 0.85);
        assertThat(result).containsEntry("category", "suspicious");
    }

    @Test
    @DisplayName("HCAD analysis for unknown user returns empty map")
    void hcadAnalysis_unknownUser_returnsEmpty() {
        Map<Object, Object> result = store.getHcadAnalysis("ghost-user");

        assertThat(result).isEmpty();
    }
}
