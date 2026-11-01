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
 * QF-49: a per-session or per-user map past its 10,000 keys releases the keys whose expiry comes first, so the records
 * written most recently stay, as they would in Redis, whatever their hash order.
 */
class InMemorySecurityContextDataStoreBoundOrderTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
            Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);

    @Test
    void pastTheBoundTheSessionsWhoseRecordsExpireFirstGo() {
        for (int session = 0; session < 10_000; session++) {
            store.addSessionDecision("session-" + session, "decision");
            clock.advance(Duration.ofMillis(1));
        }
        // Written again, these sessions' records now expire last.
        for (int session = 0; session < 100; session++) {
            store.addSessionDecision("session-" + session, "again");
            clock.advance(Duration.ofMillis(1));
        }
        for (int session = 10_000; session < 10_100; session++) {
            store.addSessionDecision("session-" + session, "decision");
            clock.advance(Duration.ofMillis(1));
        }

        assertThat(store.keyCounts()).containsEntry("sessionDecisions", 10_000);
        for (int session = 0; session < 100; session++) {
            assertThat(store.getRecentSessionDecisions("session-" + session, 2)).as("session-%d", session)
                    .containsExactly("decision", "again");
        }
        for (int session = 100; session < 200; session++) {
            assertThat(store.getRecentSessionDecisions("session-" + session, 2)).as("session-%d", session).isEmpty();
        }
        for (int session = 10_000; session < 10_100; session++) {
            assertThat(store.getRecentSessionDecisions("session-" + session, 2)).as("session-%d", session)
                    .containsExactly("decision");
        }
    }

    @Test
    void pastTheBoundTheUsersWhoseRecordsExpireFirstGo() {
        for (int user = 0; user < 10_050; user++) {
            store.holdVerificationLearning("user-" + user, "request", "{}");
            store.trackUserSession("user-" + user, "session-" + user);
            clock.advance(Duration.ofMillis(1));
        }

        assertThat(store.keyCounts()).containsEntry("verificationLearning", 10_000)
                .containsEntry("userSessions", 10_000);
        for (int user = 0; user < 50; user++) {
            assertThat(store.getUserSessions("user-" + user)).as("user-%d", user).isEmpty();
            assertThat(store.takeVerificationLearning("user-" + user, "request")).as("user-%d", user).isNull();
        }
        for (int user = 50; user < 10_050; user++) {
            assertThat(store.getUserSessions("user-" + user)).as("user-%d", user).containsExactly("session-" + user);
        }
        assertThat(store.takeVerificationLearning("user-10049", "request")).isEqualTo("{}");
    }
}
