package io.contexa.contexacore.autonomous.store;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class InMemorySecurityContextDataStoreTtlTest {

    @Test
    @DisplayName("soar execution is retrievable immediately and expires after the configured TTL")
    void soarExecution_expiresAfterTtl() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
                Duration.ofHours(24),
                Duration.ofMillis(200),
                Duration.ofDays(7));

        store.storeSoarExecution("event-soar", "playbook-result");

        assertThat(store.peekSoarExecution("event-soar"))
                .as("soar data must be visible right after storeSoarExecution")
                .isEqualTo("playbook-result");

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() -> assertThat(store.peekSoarExecution("event-soar"))
                        .as("soar data must expire after TTL")
                        .isNull());
    }

    @Test
    @DisplayName("tracked user sessions expire after the configured TTL")
    void userSessions_expireAfterTtl() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
                Duration.ofHours(24),
                Duration.ofDays(7),
                Duration.ofMillis(200));

        store.trackUserSession("user-track", "session-a");
        store.trackUserSession("user-track", "session-b");

        assertThat(store.peekUserSessions("user-track"))
                .as("sessions must be visible immediately after trackUserSession")
                .containsExactlyInAnyOrder("session-a", "session-b");

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() -> assertThat(store.peekUserSessions("user-track"))
                        .as("user sessions must expire after TTL")
                        .isEmpty());
    }
}
