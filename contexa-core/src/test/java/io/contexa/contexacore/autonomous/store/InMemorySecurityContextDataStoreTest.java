package io.contexa.contexacore.autonomous.store;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class InMemorySecurityContextDataStoreTest {

    private InMemorySecurityContextDataStore store;

    @BeforeEach
    void setUp() {
        store = new InMemorySecurityContextDataStore();
    }

    @Test
    @DisplayName("addSessionAction and getRecentSessionActions returns stored actions")
    void addSessionAction_getRecentSessionActions_returnsActions() {
        store.addSessionAction("session1", "LOGIN");
        store.addSessionAction("session1", "VIEW_PROFILE");
        store.addSessionAction("session1", "LOGOUT");

        List<String> actions = store.getRecentSessionActions("session1", 2);

        assertThat(actions).hasSize(2);
        assertThat(actions).containsExactly("VIEW_PROFILE", "LOGOUT");
    }

    @Test
    @DisplayName("getRecentSessionActions returns empty list for unknown session")
    void getRecentSessionActions_unknownSession_returnsEmptyList() {
        List<String> actions = store.getRecentSessionActions("unknown", 10);

        assertThat(actions).isEmpty();
    }

    @Test
    @DisplayName("getRecentSessionActions returns all actions when count exceeds size")
    void getRecentSessionActions_countExceedsSize_returnsAll() {
        store.addSessionAction("session1", "ACTION_A");
        store.addSessionAction("session1", "ACTION_B");

        List<String> actions = store.getRecentSessionActions("session1", 100);

        assertThat(actions).hasSize(2);
        assertThat(actions).containsExactly("ACTION_A", "ACTION_B");
    }

    @Test
    @DisplayName("Circular buffer evicts oldest actions when exceeding MAX_SESSION_ACTIONS")
    void addSessionAction_exceedsMax_evictsOldest() {
        // MAX_SESSION_ACTIONS = 100
        for (int i = 0; i < 105; i++) {
            store.addSessionAction("session1", "ACTION_" + i);
        }

        List<String> actions = store.getRecentSessionActions("session1", 200);

        assertThat(actions).hasSize(100);
        // Oldest 5 actions (ACTION_0 to ACTION_4) should be evicted
        assertThat(actions.getFirst()).isEqualTo("ACTION_5");
        assertThat(actions.getLast()).isEqualTo("ACTION_104");
    }

    @Test
    @DisplayName("Session narrative action families keep an independent sliding window")
    void sessionNarrativeActionFamilies_keepIndependentSlidingWindow() {
        store.addSessionAction("session1", "12:00 | GET /api/customer/list");
        store.addSessionNarrativeActionFamily("session1", "READ");
        store.addSessionNarrativeActionFamily("session1", "EXPORT");

        List<String> narrativeActions = store.getRecentSessionNarrativeActionFamilies("session1", 10);
        List<String> genericActions = store.getRecentSessionActions("session1", 10);

        assertThat(narrativeActions).containsExactly("READ", "EXPORT");
        assertThat(genericActions).containsExactly("12:00 | GET /api/customer/list");
    }

    @Test
    @DisplayName("Session narrative metadata round-trips protectable accesses, intervals, and timestamps")
    void sessionNarrativeMetadata_roundTripsCollectorState() {
        store.addSessionProtectableAccess("session1", "/api/customer/list");
        store.addSessionProtectableAccess("session1", "/api/customer/export");
        store.addSessionRequestInterval("session1", 900L);
        store.addSessionRequestInterval("session1", 1200L);
        store.setSessionStartedAt("session1", 1_710_000_000_000L);
        store.setSessionLastRequestTime("session1", 1_710_000_001_200L);
        store.setSessionPreviousPath("session1", "/api/customer/export");

        assertThat(store.getRecentSessionProtectableAccesses("session1", 10))
                .containsExactly("/api/customer/list", "/api/customer/export");
        assertThat(store.getRecentSessionRequestIntervals("session1", 10))
                .containsExactly(900L, 1200L);
        assertThat(store.getSessionStartedAt("session1")).isEqualTo(1_710_000_000_000L);
        assertThat(store.getSessionLastRequestTime("session1")).isEqualTo(1_710_000_001_200L);
        assertThat(store.getSessionPreviousPath("session1")).isEqualTo("/api/customer/export");
    }

    @Test
    @DisplayName("Work profile observations stay isolated per tenant scoped user")
    void workProfileObservations_stayIsolatedPerTenantScopedUser() {
        store.addWorkProfileObservation("tenant-a", "alice", "obs-a1");
        store.addWorkProfileObservation("tenant-a", "alice", "obs-a2");
        store.addWorkProfileObservation("tenant-b", "alice", "obs-b1");
        store.addWorkProfileObservation(null, "alice", "obs-global");

        assertThat(store.getRecentWorkProfileObservations("tenant-a", "alice", 10))
                .containsExactly("obs-a1", "obs-a2");
        assertThat(store.getRecentWorkProfileObservations("tenant-b", "alice", 10))
                .containsExactly("obs-b1");
        assertThat(store.getRecentWorkProfileObservations(null, "alice", 10))
                .containsExactly("obs-global");
    }

    @Test
    @DisplayName("Role scope observations and permission changes stay isolated per tenant scope")
    void roleScopeObservationsAndPermissionChanges_stayIsolatedPerTenantScope() {
        store.addRoleScopeObservation("tenant-a", "scope-1", "role-a1");
        store.addRoleScopeObservation("tenant-a", "scope-1", "role-a2");
        store.addRoleScopeObservation("tenant-b", "scope-1", "role-b1");
        store.addPermissionChangeObservation("tenant-a", "alice", "change-a1");
        store.addPermissionChangeObservation("tenant-b", "alice", "change-b1");
        store.setAuthorizationScopeState("tenant-a", "alice", "state-a");
        store.setAuthorizationScopeState("tenant-b", "alice", "state-b");

        assertThat(store.getRecentRoleScopeObservations("tenant-a", "scope-1", 10))
                .containsExactly("role-a1", "role-a2");
        assertThat(store.getRecentRoleScopeObservations("tenant-b", "scope-1", 10))
                .containsExactly("role-b1");
        assertThat(store.getRecentPermissionChangeObservations("tenant-a", "alice", 10))
                .containsExactly("change-a1");
        assertThat(store.getRecentPermissionChangeObservations("tenant-b", "alice", 10))
                .containsExactly("change-b1");
        assertThat(store.getAuthorizationScopeState("tenant-a", "alice")).isEqualTo("state-a");
        assertThat(store.getAuthorizationScopeState("tenant-b", "alice")).isEqualTo("state-b");
    }

    @Test
    @DisplayName("tryMarkEventAsProcessed returns true on first call, false on duplicate")
    void tryMarkEventAsProcessed_firstCallTrue_duplicateFalse() {
        boolean first = store.tryMarkEventAsProcessed("event-1");
        boolean duplicate = store.tryMarkEventAsProcessed("event-1");

        assertThat(first).isTrue();
        assertThat(duplicate).isFalse();
    }

    @Test
    @DisplayName("tryMarkEventAsProcessed allows different eventIds")
    void tryMarkEventAsProcessed_differentEvents_allReturnTrue() {
        assertThat(store.tryMarkEventAsProcessed("event-1")).isTrue();
        assertThat(store.tryMarkEventAsProcessed("event-2")).isTrue();
        assertThat(store.tryMarkEventAsProcessed("event-3")).isTrue();
    }

    @Test
    @DisplayName("setLastRequestTime and getLastRequestTime work correctly")
    void setLastRequestTime_getLastRequestTime_returnsTimestamp() {
        long timestamp = System.currentTimeMillis();
        store.setLastRequestTime("user1", timestamp);

        Long result = store.getLastRequestTime("user1");

        assertThat(result).isEqualTo(timestamp);
    }

    @Test
    @DisplayName("getLastRequestTime returns null for unknown user")
    void getLastRequestTime_unknownUser_returnsNull() {
        Long result = store.getLastRequestTime("unknown");

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("setPreviousPath and getPreviousPath work correctly")
    void setPreviousPath_getPreviousPath_returnsPath() {
        store.setPreviousPath("user1", "/api/users");

        String result = store.getPreviousPath("user1");

        assertThat(result).isEqualTo("/api/users");
    }

    @Test
    @DisplayName("getPreviousPath returns null for unknown user")
    void getPreviousPath_unknownUser_returnsNull() {
        String result = store.getPreviousPath("unknown");

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("setPreviousPath overwrites existing path")
    void setPreviousPath_overwritesExisting() {
        store.setPreviousPath("user1", "/api/v1");
        store.setPreviousPath("user1", "/api/v2");

        assertThat(store.getPreviousPath("user1")).isEqualTo("/api/v2");
    }
}
