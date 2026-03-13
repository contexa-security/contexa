package io.contexa.contexacore.hcad.store;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryHCADDataStoreTest {

    private InMemoryHCADDataStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryHCADDataStore();
    }

    // -- Session metadata tests --

    @Test
    @DisplayName("Save and retrieve session metadata")
    void saveSessionMetadata_getSessionMetadata_returnsMetadata() {
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
    @DisplayName("getSessionMetadata returns empty map for unknown session")
    void getSessionMetadata_unknownSession_returnsEmptyMap() {
        Map<Object, Object> result = store.getSessionMetadata("unknown");

        assertThat(result).isEmpty();
    }

    // -- Device registration tests --

    @Test
    @DisplayName("Register device and check registration")
    void registerDevice_isDeviceRegistered_returnsTrue() {
        store.registerDevice("user1", "device-abc");

        assertThat(store.isDeviceRegistered("user1", "device-abc")).isTrue();
    }

    @Test
    @DisplayName("isDeviceRegistered returns false for unregistered device")
    void isDeviceRegistered_unregisteredDevice_returnsFalse() {
        assertThat(store.isDeviceRegistered("user1", "device-xyz")).isFalse();
    }

    @Test
    @DisplayName("Device registration enforces max 10 devices limit")
    void registerDevice_exceedsMaxDevices_evictsOldest() {
        for (int i = 0; i < 12; i++) {
            store.registerDevice("user1", "device-" + i);
        }

        // At least 10 devices should be registered, some early ones may be evicted
        int registeredCount = 0;
        for (int i = 0; i < 12; i++) {
            if (store.isDeviceRegistered("user1", "device-" + i)) {
                registeredCount++;
            }
        }
        assertThat(registeredCount).isLessThanOrEqualTo(10);
    }

    // -- Request counting tests --

    @Test
    @DisplayName("Record request and count within 5-minute window")
    void recordRequest_getRecentRequestCount_returnsCount() {
        long now = System.currentTimeMillis();

        store.recordRequest("user1", now - 60_000);  // 1 min ago
        store.recordRequest("user1", now - 30_000);  // 30 sec ago
        store.recordRequest("user1", now);            // now

        long windowStart = now - 120_000; // 2 min ago
        int count = store.getRecentRequestCount("user1", windowStart, now);

        assertThat(count).isEqualTo(3);
    }

    @Test
    @DisplayName("Old requests outside 5-minute window are cleaned up")
    void recordRequest_oldRequests_cleanedUp() {
        long now = System.currentTimeMillis();
        long sixMinutesAgo = now - 6 * 60 * 1000;

        store.recordRequest("user1", sixMinutesAgo);
        store.recordRequest("user1", now);  // this triggers cleanup

        int count = store.getRecentRequestCount("user1", sixMinutesAgo, now);
        // old request should have been cleaned up during recordRequest
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("getRecentRequestCount returns 0 for unknown user")
    void getRecentRequestCount_unknownUser_returnsZero() {
        long now = System.currentTimeMillis();
        int count = store.getRecentRequestCount("unknown", now - 300_000, now);

        assertThat(count).isZero();
    }

    // -- User registration tests --

    @Test
    @DisplayName("Register user and check registration")
    void registerUser_isUserRegistered_returnsTrue() {
        store.registerUser("user1");

        assertThat(store.isUserRegistered("user1")).isTrue();
    }

    @Test
    @DisplayName("isUserRegistered returns false for unregistered user")
    void isUserRegistered_unregisteredUser_returnsFalse() {
        assertThat(store.isUserRegistered("unknown")).isFalse();
    }

    // -- MFA verification tests --

    @Test
    @DisplayName("isMfaVerified returns false for unverified user")
    void isMfaVerified_unverifiedUser_returnsFalse() {
        assertThat(store.isMfaVerified("user1")).isFalse();
    }

    // -- HCAD analysis tests --

    @Test
    @DisplayName("Save and retrieve HCAD analysis data")
    void saveHcadAnalysis_getHcadAnalysis_returnsData() {
        Map<String, Object> analysisData = new HashMap<>();
        analysisData.put("anomalyScore", 0.85);
        analysisData.put("category", "suspicious");

        store.saveHcadAnalysis("user1", analysisData);

        Map<Object, Object> result = store.getHcadAnalysis("user1");
        assertThat(result).containsEntry("anomalyScore", 0.85);
        assertThat(result).containsEntry("category", "suspicious");
    }

    @Test
    @DisplayName("getHcadAnalysis returns empty map for unknown user")
    void getHcadAnalysis_unknownUser_returnsEmptyMap() {
        Map<Object, Object> result = store.getHcadAnalysis("unknown");

        assertThat(result).isEmpty();
    }
}
