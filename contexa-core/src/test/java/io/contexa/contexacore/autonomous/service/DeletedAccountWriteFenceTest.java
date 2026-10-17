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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DeletedAccountWriteFenceTest {

    private static final String USER = "deleted-user";
    private static final Duration RETENTION = Duration.ofMinutes(13);

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
            Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);
    private final DeletedAccountWriteFence fence = new DeletedAccountWriteFence(store, RETENTION, clock);

    @Test
    @DisplayName("a write for a request taken in before the deletion is discarded and counted; a later one is kept")
    void aWriteForARequestTakenInBeforeTheDeletionIsDiscarded() {
        long before = clock.millis() - 1;
        fence.markDeleted(USER);
        long after = clock.millis() + 1_000;

        assertThat(fence.discards(DeletedAccountWriteFence.DECISION_DOCUMENT, USER, before)).isTrue();
        assertThat(fence.discards(DeletedAccountWriteFence.DECISION_DOCUMENT, USER, after)).isFalse();
        assertThat(fence.discards(DeletedAccountWriteFence.DECISION_DOCUMENT, "other-user", before)).isFalse();
        assertThat(fence.discardedWrites()).isEqualTo(Map.of(DeletedAccountWriteFence.DECISION_DOCUMENT, 1L));
    }

    @Test
    @DisplayName("the deletion is forgotten once its retention has passed")
    void theDeletionIsForgottenOnceItsRetentionHasPassed() {
        long before = clock.millis() - 1;
        fence.markDeleted(USER);

        clock.advance(RETENTION.minusSeconds(1));
        assertThat(fence.fenced(USER, before)).isTrue();
        clock.advance(Duration.ofSeconds(1));
        assertThat(fence.fenced(USER, before)).isFalse();
    }

    @Test
    @DisplayName("a request is compared at the time the engine took it in, not at the time its host states")
    void aRequestIsComparedAtTheTimeTheEngineTookItIn() {
        // A host may state the request's time on its own clock (the showcase's company clock).
        Instant hostTime = Instant.parse("2026-01-05T09:00:00Z");
        SecurityEvent takenIn = SecurityEvent.builder().userId(USER).timestamp(hostTime).build();
        takenIn.addMetadata(DeletedAccountWriteFence.TAKEN_IN_AT, 1_234L);
        SecurityEvent notTakenIn = SecurityEvent.builder().userId(USER).timestamp(hostTime).build();

        assertThat(fence.takenInAt(takenIn)).isEqualTo(1_234L);
        long now = clock.millis();
        assertThat(fence.takenInAt(notTakenIn)).isBetween(now, clock.millis());
    }

    @Test
    @DisplayName("a deletion is remembered for every attempt the event budget allows an analysis, and a margin")
    void theRetentionCoversEveryAttemptOfAnAnalysis() {
        assertThat(DeletedAccountWriteFence.retention(180_000L, 3, 60_000L)).isEqualTo(Duration.ofSeconds(780));
        assertThat(DeletedAccountWriteFence.retention(180_000L, 0, 60_000L)).isEqualTo(Duration.ofSeconds(240));
    }
}
