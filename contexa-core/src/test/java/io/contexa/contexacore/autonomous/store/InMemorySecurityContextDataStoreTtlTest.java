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
