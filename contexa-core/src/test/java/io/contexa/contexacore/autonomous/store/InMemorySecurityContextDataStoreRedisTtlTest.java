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

import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: the in-memory store forgets a per-session or per-user record when RedisSecurityContextDataStore lets the same
 * key expire (session activity 10 min, session decisions 24 h, user activity 10 min, learning 30 days, each counted
 * from the key's last write or the read that refreshes it), and every such map keeps at most 10,000 keys.
 */
class InMemorySecurityContextDataStoreRedisTtlTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
            Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);

    @Test
    void aStoppedRequestsFactsAreKeptThirtyDaysAfterTheUsersLastHold() {
        store.holdVerificationLearning("alice", "request-1", "{\"facts\":1}");
        clock.advance(Duration.ofDays(29));
        store.removeExpiredEntries();
        assertThat(store.takeVerificationLearning("alice", "request-1")).isEqualTo("{\"facts\":1}");

        store.holdVerificationLearning("bob", "request-2", "{\"facts\":2}");
        clock.advance(Duration.ofDays(31));
        store.removeExpiredEntries();

        assertThat(store.takeVerificationLearning("bob", "request-2")).isNull();
        assertThat(store.keyCounts()).containsEntry("verificationLearning", 0);
    }

    @Test
    void theRequestsHeldForPromotionAreKeptThirtyDays() {
        store.holdPromotionLearning("carol", "request-3", "{}");

        clock.advance(Duration.ofDays(31));
        store.removeExpiredEntries();

        assertThat(store.promotionLearning("carol")).isEmpty();
        assertThat(store.keyCounts()).containsEntry("promotionLearning", 0);
    }

    @Test
    void aSessionsActivityGoesAfterTenIdleMinutesAndItsDecisionsAfterADay() {
        store.setSessionStartedAt("session-1", 1L);
        store.addSessionNarrativeActionFamily("session-1", "READ", 1L);
        store.recordSessionLastRequest("session-1", 1L, "/api/a");
        store.addSessionDecision("session-1", "decision");
        store.addSessionAction("session-1", "action");

        clock.advance(Duration.ofMinutes(9));
        // The Redis store refreshes the session's start on every read of it.
        assertThat(store.getSessionStartedAt("session-1")).isEqualTo(1L);
        clock.advance(Duration.ofMinutes(9));
        store.removeExpiredEntries();

        assertThat(store.getSessionStartedAt("session-1")).isEqualTo(1L);
        assertThat(store.getRecentSessionNarrativeActionFamilies("session-1", 10)).isEmpty();
        assertThat(store.getSessionLastRequestTime("session-1")).isNull();
        assertThat(store.getSessionPreviousPath("session-1")).isNull();
        assertThat(store.getRecentSessionDecisions("session-1", 10)).containsExactly("decision");
        assertThat(store.getRecentSessionActions("session-1", 10)).containsExactly("action");

        clock.advance(Duration.ofHours(24));
        store.removeExpiredEntries();

        assertThat(store.getSessionStartedAt("session-1")).isNull();
        assertThat(store.getRecentSessionDecisions("session-1", 10)).isEmpty();
        assertThat(store.getRecentSessionActions("session-1", 10)).isEmpty();
    }

    @Test
    void aUsersActivityGoesAfterTenMinutesAndWhatIsLearnedAfterThirtyDays() {
        store.setLastRequestTime("dave", 1L);
        store.setPreviousPath("dave", "/api/a");
        store.addWorkProfileObservation("tenant", "dave", "{}");
        store.addPermissionChangeObservation("tenant", "dave", "{}");
        store.setAuthorizationScopeState("tenant", "dave", "{}");
        store.addRoleScopeObservation("tenant", "scope-1", "{}");

        clock.advance(Duration.ofMinutes(11));
        store.removeExpiredEntries();

        assertThat(store.getLastRequestTime("dave")).isNull();
        assertThat(store.getPreviousPath("dave")).isNull();
        assertThat(store.getRecentWorkProfileObservations("tenant", "dave", 10)).hasSize(1);

        clock.advance(Duration.ofDays(30));
        store.removeExpiredEntries();

        assertThat(store.getRecentWorkProfileObservations("tenant", "dave", 10)).isEmpty();
        assertThat(store.getRecentPermissionChangeObservations("tenant", "dave", 10)).isEmpty();
        assertThat(store.peekAuthorizationScopeState("tenant", "dave")).isNull();
        assertThat(store.getRecentRoleScopeObservations("tenant", "scope-1", 10)).isEmpty();
    }

    @Test
    void everyPerSessionAndPerUserMapKeepsAtMostTenThousandKeys() {
        for (int i = 0; i <= 10_000; i++) {
            store.addSessionDecision("session-" + i, "decision");
            store.holdVerificationLearning("user-" + i, "request", "{}");
            store.holdPromotionLearning("user-" + i, "request", "{}");
            store.trackUserSession("user-" + i, "session-" + i);
        }

        assertThat(store.keyCounts()).allSatisfy((map, keys) -> assertThat(keys).as(map)
                .isLessThanOrEqualTo(10_000));
    }
}
